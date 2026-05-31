from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pcs.security import generate_self_signed_cert


def generate(cert_dir: Path, cn: str = "localhost") -> tuple[Path, Path]:
    certfile = cert_dir / "server.crt"
    keyfile = cert_dir / "server.key"
    if certfile.exists() and keyfile.exists():
        print(f"Certyfikaty już istnieją: {certfile}")
        return certfile, keyfile
    generate_self_signed_cert(certfile, keyfile, cn=cn)
    print(f"Wygenerowano: {certfile}, {keyfile}")
    return certfile, keyfile


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("certs")
    cn = sys.argv[2] if len(sys.argv) > 2 else "localhost"
    generate(target, cn=cn)
