import csv
import math
import os
import re
import statistics
import subprocess
import time

from code.experiments.config import Config

_UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9._=+-]+")

SUMMARY_FIELDS = [
    "timestamp",
    "protocol",
    "profile",
    "cert_types",
    "kex_alg",
    "delay",
    "loss",
    "bandwidth",
    "fragment",
    "n",
    "mean_ms",
    "sd_ms",
    "min_ms",
    "p50_ms",
    "p95_ms",
    "max_ms",
    "timings_file",
]


def setup_dirs(config: Config):
    os.makedirs(config.exp_dir, exist_ok=True)
    os.makedirs(config.certs_dir, exist_ok=True)
    os.makedirs(config.timings_dir, exist_ok=True)
    os.makedirs(config.logs_dir, exist_ok=True)


def setup_netem(config: Config, loss, delay, bandwidth):
    for i, side in enumerate(["srv", "cli"]):
        netns_prefix = ["ip", "netns", "exec", f"{side}_{config.netns_suffix}"]
        delete_cmd = netns_prefix + [
            "tc", "qdisc", "del", "dev", f"veth_{side}", "root"
        ]
        subprocess.run(delete_cmd, check=False, stderr=subprocess.DEVNULL)

        add_cmd = netns_prefix + [
            "tc", "qdisc", "add", "dev", f"veth_{side}",
            "root", "netem", "limit", "10000",
        ]
        if loss is not None:
            add_cmd += ["loss"] + loss
        if delay is not None:
            add_cmd += ["delay"] + delay
        if bandwidth is not None:
            add_cmd += ["rate"] + [bandwidth[i % len(bandwidth)]]
        subprocess.run(add_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def run_server(config: Config, kex_alg, server_certificate, server_priv_key, key_log_file=None,
               log_name="server_log.txt", startup_wait=2):
    cmd = [
        "taskset", "-c", "1", "ip", "netns", "exec", f"srv_{config.netns_suffix}",
    ]
    if config.run_quic:
        cmd += [config.quic_server, config.server_port]
    else:
        cmd += [config.tls_server, f"{config.server_ip}:{config.server_port}"]

    cmd += [
        server_certificate,
        server_priv_key,
        f"{kex_alg}",
    ]

    env = dict(os.environ)
    if key_log_file:
        env["SSLKEYLOGFILE"] = key_log_file

    log_path = os.path.join(config.logs_dir, log_name)
    with open(log_path, "a+") as log:
        server = subprocess.Popen(cmd, stdout=log, stderr=log, env=env)

    time.sleep(startup_wait)
    if server.poll() is not None:
        raise RuntimeError(
            f"Server exited during startup with code {server.returncode}; see {log_path}"
        )
    return server


def sanitize(text):
    """Turn a human-readable label into a filesystem-friendly slug."""
    slug = _UNSAFE_CHARS.sub("_", text.replace("%", "pct"))
    return re.sub(r"_+", "_", slug).strip("_")


def get_output_paths(config: Config, identifier, loss, delay, bandwidth, kex_alg, measurements_per_config):
    details = [f"N={measurements_per_config}", f"KX={kex_alg}"]
    if loss is not None:
        details.append("Loss=" + "-".join(loss))
    if delay is not None:
        details.append("Delay=" + "-".join(delay))
    if bandwidth is not None:
        details.append("BW=" + "-".join(bandwidth))
    details.append(identifier)
    exp_details = sanitize("_".join(details))

    mode = "QUIC" if config.run_quic else "TLS"
    path = os.path.join(config.timings_dir, f"timings_{mode}_ct_{exp_details}.txt")
    log_path = os.path.join(config.logs_dir, f"Log_{mode}_ct_{exp_details}.log")
    return path, log_path


def summarize_timings(path):
    """Return summary statistics for a raw timings file, or None if empty."""
    if not os.path.exists(path):
        return None

    values = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            values.append(float(line))
    if not values:
        return None

    ordered = sorted(values)
    n = len(ordered)

    def percentile(p):
        rank = max(1, math.ceil(p / 100 * n))
        return ordered[min(rank, n) - 1]

    return {
        "n": n,
        "mean_ms": f"{statistics.fmean(ordered):.3f}",
        "sd_ms": f"{statistics.stdev(ordered):.3f}" if n > 1 else "0.000",
        "min_ms": f"{ordered[0]:.3f}",
        "p50_ms": f"{percentile(50):.3f}",
        "p95_ms": f"{percentile(95):.3f}",
        "max_ms": f"{ordered[-1]:.3f}",
    }


def summary_path(config: Config):
    return os.path.join(config.exp_dir, "summary.csv")


def append_summary_row(config: Config, row):
    path = summary_path(config)
    write_header = not os.path.exists(path) or os.path.getsize(path) == 0
    with open(path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=SUMMARY_FIELDS)
        if write_header:
            writer.writeheader()
        writer.writerow(row)
    return path


def print_summary(config: Config):
    """Print the accumulated summary.csv as an aligned table."""
    path = summary_path(config)
    if not os.path.exists(path):
        print(f"No summary written ({path} does not exist).")
        return

    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        print("Summary is empty.")
        return

    columns = ["profile", "cert_types", "delay", "loss", "fragment",
               "n", "mean_ms", "sd_ms", "p50_ms", "p95_ms"]
    widths = {
        column: max(len(column), *(len(row.get(column, "")) for row in rows))
        for column in columns
    }
    header = "  ".join(column.ljust(widths[column]) for column in columns)
    print(header)
    print("-" * len(header))
    for row in rows:
        print("  ".join(row.get(column, "").ljust(widths[column]) for column in columns))
