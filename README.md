# Post-Quantum QUIC Experiment Framework

This repository provides a standalone framework for measuring the performance of **Post-Quantum (PQ) signatures** in QUIC and TLS, specifically focusing on **Certificate Transparency (CT)** overhead.

## Project Structure

- **`setup.sh`**: One-time environment preparation. Automates tool checks, OpenSSL patching, and binary compilation.
- **`openssl_patch/`**: Contains OpenSSL 3.6.0-beta1 source and custom patches for PQ algorithm support and performance instrumentation.
- **`code/`**:
  - **`client_server/`**: Specialized C-based clients and servers designed for high-precision handshake timing.
  - **`certs/`**: Python suite for generating complex certificate chains and Signed Certificate Timestamps (SCTs) using ML-DSA (Dilithium) and other algorithms.
  - **`experiments/`**: The core orchestration engine. Manages Linux network namespaces (`ip netns`), `tc` for latency/loss simulation, and automated data collection.
- **`scripts/run_experiment.sh`**: The primary entry point for executing experiment suites with the necessary root privileges.

## Getting Started

### 1. Setup
Requires a Linux environment with root access (`sudo`) and the following tools:

| Requirement | Why |
| :--- | :--- |
| `gcc`, `make`, `perl`, `tar`, `bash` | Building OpenSSL, the demo servers, and the timing clients |
| `curl` and `wget` | Downloading OpenSSL and `uv` during setup |
| `python3` (3.8+, tested with 3.14) | Certificate generation and the experiment runner |
| `iproute2` (`ip`, `tc`) | Network namespaces and `netem` shaping |
| `util-linux` (`taskset`) | Pinning server to core 1 and client to core 2 — needs at least 3 CPUs |
| `procps` (`pkill`) | Used by `make clean` |

On Debian/Ubuntu:

```bash
sudo apt-get install -y build-essential perl python3 curl wget iproute2 util-linux procps
```

The environment must be connected to the internet. `setup.sh` downloads OpenSSL
3.6.0-beta1, applies the PQ/CT patch, builds and installs it, compiles the demo
servers and timing clients, then installs `uv` and creates `.venv` from
`requirements.txt`. Budget about 1.5 GB for the build tree, plus up to ~300 MB
per `main_tests` results directory. `setup.sh` checks for at least 2 GB of free
space before starting the OpenSSL build and exits early if there is not enough.

#### From the ZIP archive

If you received the project as `post-quantum-quick-standalone-runnable.zip`, no clone is needed:

```bash
unzip post-quantum-quick-standalone-runnable.zip
cd post-quantum-quick-standalone
sudo ./setup.sh
sudo ./scripts/run_experiment.sh --test-types test_tests
```

The archive includes the pristine OpenSSL 3.6.0-beta1 tarball under `openssl_patch/download/`,
so `setup.sh` will not download it. Internet access is still required to install `uv` and the
Python packages.

#### From a source checkout

```bash
git clone <repository-url> post-quantum-quick-standalone
cd post-quantum-quick-standalone
chmod +x setup.sh
sudo ./setup.sh
```

#### Python dependencies
`setup.sh` installs `requirements.txt` into `.venv`. The experiments need three packages:

| Package | Used by |
| :--- | :--- |
| `tqdm` | Progress bar in `code/experiments` |
| `cryptography` | Certificate and SCT generation |
| `pyasn1` | DER encoding of SCTs |

### 2. Run Experiments
Experiments must run as `root` to manage network namespaces and traffic control.
Always start them through this script: it activates the virtual environment and puts the
patched OpenSSL on `PATH`/`LD_LIBRARY_PATH`, which certificate generation and the timing
clients both need.

The script requires an explicit suite selection. Use `--test-type` (alias `--test-types`) or pass the suite name positionally.

| Suite | Command | Est. Time | Description |
| :--- | :--- | :--- | :--- |
| **Test** | `sudo ./scripts/run_experiment.sh --test-types test_tests` | ~2 mins | Quick verification of the full pipeline. |
| **Main** | `sudo ./scripts/run_experiment.sh --test-types main_tests` | ~50 hours | Full suite: 5 algorithm pairs across 3 network profiles (DC, Broadband, Mobile). |
| **Short Main** | `sudo ./scripts/run_experiment.sh --test-types short_main_tests` | ~1.5-2 hours | Same matrix as Main with 100 measurements/config and 10 warmup handshakes/run. |
| **RTT** | `sudo ./scripts/run_experiment.sh --test-types rtt_tests` | 1-2 hours | Detailed latency impact analysis across different RTTs. |

Supported suite names are `main_tests`, `short_main_tests`, `rtt_tests`, and `test_tests`. You can also pass these names directly without `--test-types`; the short aliases `short`, `rtt`, and `test` are accepted too.

#### Algorithm pairs
Each pair is `<CA key algorithm>+<SCT signing algorithm>`: the certificate chain signer and the CT log's SCT signer.

| Pair | `main_tests` | `short_main_tests` | `rtt_tests` | `test_tests` |
| :--- | :--- | :--- | :--- | :--- |
| P-256 + P-256 | datacenter, broadband, mobile | datacenter, broadband, mobile | test_rtt | test |
| MLDSA44 + P-256 | datacenter, broadband, mobile | datacenter, broadband, mobile | test_rtt | test |
| MLDSA44 + MLDSA44 | datacenter, broadband, mobile | datacenter, broadband, mobile | test_rtt | – |
| MLDSA65 + MLDSA65 | datacenter | datacenter | test_rtt | – |
| MLDSA87 + MLDSA87 | datacenter | datacenter | test_rtt | – |

#### Smaller-scale reproducibility

`short_main_tests` (alias `short`) runs the Main matrix with 100 measurements per config
and 10 warmup handshakes, which is enough to check reproducibility at reduced scale:

```bash
sudo ./scripts/run_experiment.sh --test-types short
```

Use `--dry-run` to print the planned matrix without touching network namespaces, and `--protocol tls` to benchmark the TLS binaries instead of QUIC:

```bash
sudo ./scripts/run_experiment.sh --test-types main_tests --dry-run
```

## Data & Results
All results are stored in the `results/` directory, timestamped and categorized by test suite. Each experiment generates:
- Raw handshake timings under `timings/`, one file per network config and fragment.
- A `summary.csv` with per-run statistics (`n`, mean, sd, min, p50, p95, max) and the corresponding labels.
- Detailed logs for both client and server, under `logs/`.
- The specific certificate chains used during the run, under `certs/`.

---
**Note:** The framework uses Linux network namespaces for isolation. Do not run other network-sensitive tasks while experiments are active.

## Author

Shay Gueron, University of Haifa.

## License

Copyright 2026 Shay Gueron, University of Haifa.
Licensed under the Apache License, Version 2.0 (see [LICENSE](LICENSE)).
Third-party code keeps its own copyright and license (see [NOTICE](NOTICE)).

## Acknowledgements

This work was supported by the Israel Innovation Authority, Technological Infrastructure Division, as part of the Post-Quantum Communications (PQC) Consortium.
