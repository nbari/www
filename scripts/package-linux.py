#!/usr/bin/env python3
"""Package a verified static Linux binary with the Cargo tools used by s3m."""

import argparse
from pathlib import Path
import struct
import subprocess
import tomllib

TARGETS = {
    "x86_64-unknown-linux-musl": (62, "amd64", "x86_64"),
    "aarch64-unknown-linux-musl": (183, "arm64", "aarch64"),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", choices=TARGETS)
    args = parser.parse_args()
    machine, deb_arch, rpm_arch = TARGETS[args.target]
    binary = Path("target", args.target, "release/www")
    with binary.open("rb") as stream:
        header = stream.read(20)
    if len(header) != 20 or header[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", header, 18)[0] != machine:
        raise RuntimeError(f"{binary} is not the expected 64-bit Linux executable")
    program = subprocess.check_output(["readelf", "-l", str(binary)], text=True)
    dynamic = subprocess.check_output(["readelf", "-d", str(binary)], text=True)
    if "INTERP" in program or "(NEEDED)" in dynamic:
        raise RuntimeError("Linux packages must contain a static musl binary")
    version = tomllib.loads(Path("Cargo.toml").read_text())["package"]["version"]
    output = Path("dist")
    output.mkdir(exist_ok=True)
    subprocess.run([
        "cargo", "deb", "--no-build", "--no-strip", "--target", args.target,
        "--output", str(output / f"www_{version}-1_{deb_arch}.deb"),
    ], check=True)
    subprocess.run([
        "cargo", "generate-rpm", "--target", args.target, "--arch", rpm_arch,
        "--output", str(output / f"www-{version}-1.{rpm_arch}.rpm"),
    ], check=True)


if __name__ == "__main__":
    main()
