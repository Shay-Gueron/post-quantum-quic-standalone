from dataclasses import dataclass
import os

@dataclass
class Config:
    # Directories
    exp_dir: str
    certs_dir: str
    timings_dir: str
    logs_dir: str

    # Binaries (relative to script location)
    quic_server: str = "openssl_patch/download/openssl-3.6.0-beta1/demos/quic/server/server"
    quic_client: str = "code/client_server/s_timer_ct_quic.o"
    tls_server: str = "openssl_patch/download/openssl-3.6.0-beta1/demos/guide/tls-server-block"
    tls_client: str = "code/client_server/s_timer_ct.o"

    # Network settings
    netns_suffix: str = "ns"
    server_port: str = "4433"
    server_ip: str = "10.0.0.1"

    # Experiment defaults
    max_fragment_number: int = 10
    run_quic: bool = True
    warmup_handshakes: int = 100

    @classmethod
    def from_exp_dir(cls, exp_dir: str):
        abs_exp_dir = os.path.realpath(exp_dir)
        return cls(
            exp_dir=abs_exp_dir,
            certs_dir=os.path.join(abs_exp_dir, "certs/"),
            timings_dir=os.path.join(abs_exp_dir, "timings/"),
            logs_dir=os.path.join(abs_exp_dir, "logs/")
        )
