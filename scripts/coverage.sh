#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

if ! command -v grcov >/dev/null 2>&1; then
    echo 'grcov is required; run just coverage-tools' >&2
    exit 1
fi

rust_host=$(rustc -vV | sed -n 's/^host: //p')
llvm_dir="$(rustc --print sysroot)/lib/rustlib/$rust_host/bin"
if [ ! -x "$llvm_dir/llvm-cov" ] || [ ! -x "$llvm_dir/llvm-profdata" ]; then
    echo 'Matching LLVM tools are required; run rustup component add llvm-tools-preview' >&2
    exit 1
fi

coverage_dir="$PWD/target/coverage"
profile_dir="$coverage_dir/profraw"

# Keep the instrumented build cache, but never merge profiles from earlier runs.
mkdir -p "$coverage_dir"
rm -rf "$profile_dir" "$coverage_dir/html"
rm -f "$coverage_dir/lcov" "$coverage_dir/lcov.info" "$coverage_dir/coverage.profdata"
mkdir -p "$profile_dir"

export CARGO_TARGET_DIR="$coverage_dir/build"
export CARGO_INCREMENTAL=0
export LLVM_PROFILE_FILE="$profile_dir/www-%p-%m.profraw"
export RUSTFLAGS='-Cinstrument-coverage -Ccodegen-units=1'
export RUSTDOCFLAGS="$RUSTFLAGS"
unset CARGO_ENCODED_RUSTFLAGS

# Includes the in-process Rust ACME CA and example safeguard tests. The public
# Let's Encrypt test remains ignored; no benchmark load generator is executed.
cargo test --locked --all-features --all-targets

# Timeout/shutdown tests intentionally terminate helper processes, which can
# interrupt a profile write. LLVM warns about partial files and retains valid
# profiles; the merge still fails if none can be read.
"$llvm_dir/llvm-profdata" merge --sparse --failure-mode=all \
    "$profile_dir" --output "$coverage_dir/coverage.profdata"

grcov "$coverage_dir/coverage.profdata" \
    --binary-path "$CARGO_TARGET_DIR/debug" \
    --source-dir "$PWD" \
    --llvm-path "$llvm_dir" \
    --llvm \
    --keep-only 'src/**' \
    --ignore-not-existing \
    --output-types html,lcov \
    --output-path "$coverage_dir"

mv "$coverage_dir/lcov" "$coverage_dir/lcov.info"
if ! grep -q '^SF:' "$coverage_dir/lcov.info" \
    || ! grep -Eq '^DA:[0-9]+,[1-9][0-9]*(,|$)' "$coverage_dir/lcov.info"; then
    echo 'Coverage report contains no executed application source lines' >&2
    exit 1
fi

printf 'HTML coverage: %s\nLCOV coverage: %s\n' \
    "$coverage_dir/html/index.html" "$coverage_dir/lcov.info"
