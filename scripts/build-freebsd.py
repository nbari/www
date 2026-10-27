#!/usr/bin/env python3
"""Cross-build the existing FreeBSD release targets with an official ABI sysroot."""

import argparse
import hashlib
import os
from pathlib import Path
import shlex
import shutil
import subprocess


TARGETS = {
    "x86_64-unknown-freebsd": "amd64",
    "aarch64-unknown-freebsd": "arm64/aarch64",
    "i686-unknown-freebsd": "i386",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", choices=TARGETS)
    args = parser.parse_args()
    target = args.target
    cache = Path("target/freebsd-sysroots", target).resolve()
    cache.mkdir(parents=True, exist_ok=True)
    sdk = cache / "sysroot"
    marker = sdk / ".complete"
    if not marker.exists():
        base = f"https://archive.freebsd.org/old-releases/{TARGETS[target]}/14.3-RELEASE"
        manifest_path = cache / "MANIFEST"
        subprocess.run(["cargo", "run", "--locked", "--example", "fetch", "--", f"{base}/MANIFEST", str(manifest_path)], check=True)
        manifest = manifest_path.read_text()
        expected = next(line.split()[1] for line in manifest.splitlines() if line.split()[0] == "base.txz")
        archive = cache / "base.txz"
        print(f"Downloading FreeBSD 14.3 ABI sysroot for {target}", flush=True)
        subprocess.run(["cargo", "run", "--locked", "--example", "fetch", "--", f"{base}/base.txz", str(archive)], check=True)
        with archive.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != expected:
            raise RuntimeError("FreeBSD base.txz checksum mismatch")
        sdk.mkdir(exist_ok=True)
        subprocess.run(["tar", "-xJf", str(archive), "-C", str(sdk), "./lib", "./usr/lib", "./usr/include"], check=True)
        marker.touch()
    sysroot = Path(subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip())
    host = next(line.split(": ", 1)[1] for line in subprocess.check_output(["rustc", "-vV"], text=True).splitlines() if line.startswith("host: "))
    lld = sysroot / "lib/rustlib" / host / "bin/rust-lld"
    clang = shutil.which("clang")
    if not clang or not lld.is_file():
        raise RuntimeError("clang and the Rust toolchain's rust-lld are required")
    linker = cache / "linker"
    lld_driver = cache / "ld.lld"
    lld_driver.write_text(f'#!/bin/sh\nexec {shlex.quote(str(lld))} -flavor gnu "$@"\n')
    lld_driver.chmod(0o755)
    linker.write_text(f'#!/bin/sh\nexec {shlex.quote(clang)} --target={target} --sysroot={shlex.quote(str(sdk))} -fuse-ld={shlex.quote(str(lld_driver))} "$@"\n')
    linker.chmod(0o755)
    subprocess.run(["rustup", "target", "add", target], check=True)
    env = os.environ.copy()
    key = target.replace("-", "_")
    env[f"CARGO_TARGET_{key.upper()}_LINKER"] = str(linker)
    env[f"CC_{key}"] = clang
    env[f"CFLAGS_{key}"] = f"--target={target} --sysroot={sdk}"
    subprocess.run(["cargo", "build", "--release", "--locked", "--bin", "www", "--target", target], env=env, check=True)


if __name__ == "__main__":
    main()
