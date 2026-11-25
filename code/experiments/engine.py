import itertools
import os
import subprocess
import time

from code.experiments.config import Config
from code.experiments.helpers import (
    append_summary_row,
    get_output_paths,
    setup_netem,
    summarize_timings,
)


def _join(values):
    return "-".join(values) if values is not None else ""


def run_experiment_logic(config: Config, identifier, losses, delays, bandwidth, kex_alg, measurements_per_config, fragment_share, pbar=None, summary_context=None):
    for delay, loss in itertools.product(delays, losses):
        if pbar is not None:
            pbar.set_description(f"{identifier} | Delay: {delay}, Loss: {loss}")

        path, log_path = get_output_paths(
            config, identifier, loss, delay, bandwidth, kex_alg, measurements_per_config
        )
        setup_netem(config, loss, delay, bandwidth)
        time.sleep(2)  # wait for netem to settle

        with open(path, "w") as f, open(log_path, "w") as err:
            cmd = [
                "taskset", "-c", "2", "ip", "netns", "exec", f"cli_{config.netns_suffix}",
            ]
            if config.run_quic:
                cmd += [config.quic_client]
            else:
                cmd += [config.tls_client]

            cmd += [kex_alg, str(fragment_share)]

            if config.run_quic:
                cmd += [config.server_ip, config.server_port]
            else:
                cmd += [f"{config.server_ip}:{config.server_port}"]

            cmd += [
                os.path.realpath(os.path.join(config.certs_dir, "root.crt")),
                os.path.realpath(os.path.join(config.certs_dir, "ct_log_list.cnf"))
            ]

            env = dict(os.environ)
            env["WARMUP_COUNT"] = str(config.warmup_handshakes)
            completed = subprocess.run(cmd, stdout=f, stderr=err, env=env)
            if completed.returncode != 0:
                raise RuntimeError(
                    f"Client exited with code {completed.returncode} for {identifier} "
                    f"(delay={_join(delay)}, loss={_join(loss)}); see {log_path}"
                )

        stats = summarize_timings(path)
        if stats is not None:
            row = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "protocol": "QUIC" if config.run_quic else "TLS",
                "delay": _join(delay),
                "loss": _join(loss),
                "bandwidth": _join(bandwidth),
                "timings_file": os.path.basename(path),
                **(summary_context or {}),
                **stats,
            }
            append_summary_row(config, row)
            print(
                f"  {identifier} | delay={row['delay'] or '-'} loss={row['loss'] or '-'}"
                f" -> n={stats['n']} mean={stats['mean_ms']}ms sd={stats['sd_ms']}ms"
                f" p95={stats['p95_ms']}ms"
            )

        if pbar is not None:
            pbar.update(1)


class ExperimentProfile:
    def __init__(self, identifier, losses, delays, bandwidth, measurements_per_config):
        self.identifier = identifier
        self.losses = losses
        self.delays = delays
        self.bandwidth = bandwidth
        self.measurements_per_config = measurements_per_config

    def fragments(self):
        return len(self.measurements_per_config)

    def run(self, config: Config, cert_types, fragment_index=None, kex_alg="X25519MLKEM768", pbar=None):
        if fragment_index is None or fragment_index < 0 or fragment_index >= self.fragments():
            return

        identifier = f"Frag {fragment_index} | {cert_types} | {self.identifier}"

        run_experiment_logic(
            config=config,
            identifier=identifier,
            losses=self.losses,
            delays=self.delays,
            bandwidth=self.bandwidth,
            kex_alg=kex_alg,
            measurements_per_config=sum(self.measurements_per_config),
            fragment_share=self.measurements_per_config[fragment_index],
            pbar=pbar,
            summary_context={
                "profile": self.identifier,
                "cert_types": cert_types,
                "kex_alg": kex_alg,
                "fragment": fragment_index,
            },
        )
