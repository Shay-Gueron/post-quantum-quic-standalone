import argparse
import os
import shutil
import subprocess
import time
from dataclasses import replace

import tqdm

from code.certs.setup import setup_certificate
from code.experiments.config import Config
from code.experiments.helpers import print_summary, run_server, sanitize, setup_dirs
from code.experiments.test_suites import get_test_suites

DEFAULT_WARMUP_HANDSHAKES = 100
SHORT_WARMUP_HANDSHAKES = 10
BYTES_PER_HANDSHAKE = 500  # observed ~340 B of client log per handshake, with margin


def parse_args():
    parser = argparse.ArgumentParser(description="Run timing results with various configs")
    parser.add_argument("--kex-alg", type=str, default="X25519MLKEM768", choices=["X25519MLKEM768"],
                        help="Key exchange algorithm to use with all results")
    parser.add_argument("--exp-dir", type=str, default="results",
                        help="Experiments working directory. Results, logs and generated resources will be saved there")
    parser.add_argument("--base-measurements-count", type=int, default=None,
                        help="Total handshakes per network config, split across fragments")
    parser.add_argument("--test-type", type=str, default="main_tests",
                        choices=["main_tests", "short_main_tests", "rtt_tests", "test_tests"],
                        help="Type of tests to run")
    parser.add_argument("--warmup-handshakes", type=int, default=None,
                        help=f"Warmup handshakes per client run (default: {SHORT_WARMUP_HANDSHAKES} "
                             f"for short_main_tests, {DEFAULT_WARMUP_HANDSHAKES} otherwise)")
    parser.add_argument("--pairs", type=str, default="",
                        help="Optional comma-separated pair filter, e.g. P-256+P-256,MLDSA44+P-256")
    parser.add_argument("--profiles", type=str, default="",
                        help="Optional comma-separated profile filter, e.g. datacenter,broadband")
    parser.add_argument("--protocol", type=str, default="quic", choices=["quic", "tls"],
                        help="Transport to benchmark")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the planned runs and exit without touching network namespaces")
    parser.add_argument("--ignore-disk-space", action="store_true",
                        help="Start even if the free space looks too small for the run")
    return parser.parse_args()


def count_progress_steps(test_plan):
    """Number of client runs, i.e. progress-bar ticks."""
    total = 0
    for profiles in test_plan.values():
        for profile in profiles:
            total += profile.fragments() * len(profile.delays) * len(profile.losses)
    return total


def count_handshakes(test_plan, warmup_handshakes):
    total = 0
    for profiles in test_plan.values():
        for profile in profiles:
            networks = len(profile.delays) * len(profile.losses)
            total += sum(profile.measurements_per_config) * networks
            total += warmup_handshakes * profile.fragments() * networks
    return total


def estimate_output_bytes(test_plan, warmup_handshakes):
    return count_handshakes(test_plan, warmup_handshakes) * BYTES_PER_HANDSHAKE


def parse_filter(value):
    return {item.strip() for item in value.split(",") if item.strip()}


def filter_plan(test_plan, pairs, profiles):
    if pairs:
        test_plan = {
            key: value for key, value in test_plan.items()
            if f"{key[0]}+{key[1]}" in pairs
        }
    if profiles:
        filtered = {}
        for key, plan_profiles in test_plan.items():
            kept = [profile for profile in plan_profiles if profile.identifier in profiles]
            if kept:
                filtered[key] = kept
        test_plan = filtered
    if not test_plan:
        raise SystemExit("Filter matched no test plan entries; check --pairs/--profiles.")
    return test_plan


def print_plan(test_plan, warmup_handshakes):
    for (ca_type, ct_type), profiles in test_plan.items():
        for profile in profiles:
            fragments = profile.fragments()
            per_config = sum(profile.measurements_per_config)
            network_configs = len(profile.delays) * len(profile.losses)
            print(
                f"{ca_type}+{ct_type} | {profile.identifier}: "
                f"{network_configs} network configs x {fragments} fragments "
                f"({per_config} handshakes/config) -> "
                f"{per_config * network_configs} handshakes"
            )
    print(f"total client runs: {count_progress_steps(test_plan)}")
    print(f"total handshakes: {count_handshakes(test_plan, warmup_handshakes)} "
          f"(includes {warmup_handshakes} warmup/run)")


def main():
    args = parse_args()
    config = Config.from_exp_dir(args.exp_dir)
    config.run_quic = args.protocol == "quic"

    if args.warmup_handshakes is None:
        args.warmup_handshakes = (SHORT_WARMUP_HANDSHAKES if args.test_type == "short_main_tests"
                                  else DEFAULT_WARMUP_HANDSHAKES)
    if args.base_measurements_count is None:
        args.base_measurements_count = 10**2 if args.test_type == "short_main_tests" else 10**4
    config.warmup_handshakes = args.warmup_handshakes

    test_plan = get_test_suites(
        args.base_measurements_count,
        config.max_fragment_number,
        short_base_count=args.base_measurements_count,
    )[args.test_type]
    test_plan = filter_plan(test_plan, parse_filter(args.pairs), parse_filter(args.profiles))

    if args.dry_run:
        print(f"Suite: {args.test_type} | protocol: {args.protocol.upper()} | "
              f"base measurements: {args.base_measurements_count} | "
              f"warmup/run: {args.warmup_handshakes}")
        print_plan(test_plan, args.warmup_handshakes)
        print(f"estimated output: {estimate_output_bytes(test_plan, args.warmup_handshakes) / 1e6:.0f} MB")
        return

    if args.test_type in ("main_tests", "short_main_tests") and args.base_measurements_count < config.max_fragment_number:
        raise SystemExit(
            f"--base-measurements-count must be at least {config.max_fragment_number} for "
            f"{args.test_type} (one handshake per fragment), got {args.base_measurements_count}."
        )

    setup_dirs(config)

    needed = estimate_output_bytes(test_plan, args.warmup_handshakes)
    free = shutil.disk_usage(config.exp_dir).free
    if free < needed and not args.ignore_disk_space:
        raise SystemExit(
            f"Not enough free space in {config.exp_dir}: this run writes roughly "
            f"{needed / 1e6:.0f} MB of logs and timings, but only {free / 1e6:.0f} MB is free. "
            f"Free space, use a different --exp-dir, or pass --ignore-disk-space."
        )

    print("Setting up network namespaces...")
    with open(os.path.join(config.logs_dir, "setup_log.txt"), "a+") as f:
        subprocess.run(["bash", os.path.join(os.path.dirname(__file__), "netns_setup.sh")],
                       check=True, stdout=f, stderr=f)

    with tqdm.tqdm(total=count_progress_steps(test_plan), desc="Overall Progress") as pbar:
        for ca_type, ct_type in test_plan:
            time.sleep(0.5)
            cert_types = f"{ca_type}+{ct_type}"
            pair_config = replace(
                config,
                certs_dir=os.path.join(config.certs_dir, sanitize(cert_types)) + "/",
            )
            os.makedirs(pair_config.certs_dir, exist_ok=True)

            with open(os.path.join(config.logs_dir, "setup_log.txt"), "a+") as f:
                setup_certificate(ca_type, ct_type, pair_config.certs_dir, stdout=f, stderr=f)

            server = None
            try:
                server = run_server(
                    config=pair_config,
                    kex_alg=args.kex_alg,
                    server_certificate=os.path.join(pair_config.certs_dir, "leaf_100.pem"),
                    server_priv_key=os.path.join(pair_config.certs_dir, "leaf.priv.key"),
                    key_log_file=os.path.join(pair_config.certs_dir, "keylog.txt"),
                    log_name=f"server_log_{sanitize(cert_types)}.txt",
                )

                for test_profile in test_plan[(ca_type, ct_type)]:
                    for fragment_index in range(test_profile.fragments()):
                        time.sleep(0.5)
                        test_profile.run(
                            config=pair_config,
                            cert_types=cert_types,
                            fragment_index=fragment_index,
                            kex_alg=args.kex_alg,
                            pbar=pbar,
                        )
            finally:
                if server is not None:
                    server.terminate()

    print("All results done. Summary:")
    print_summary(config)


if __name__ == "__main__":
    main()
