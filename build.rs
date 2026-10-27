use std::{env, fs, io::Write, path::PathBuf, process::Command};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-env-changed=BUILT_OVERRIDE_www_GIT_COMMIT_HASH");
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    if let Ok(output) = Command::new("git")
        .current_dir(&manifest)
        .args([
            "rev-parse",
            "--git-path",
            "HEAD",
            "--git-path",
            "refs",
            "--git-path",
            "packed-refs",
        ])
        .output()
        && output.status.success()
    {
        for path in String::from_utf8(output.stdout)?.lines() {
            if manifest.join(path).exists() {
                println!("cargo::rerun-if-changed={path}");
            }
        }
    }

    // Cargo packages retain their source commit even without a Git checkout.
    let vcs = manifest.join(".cargo_vcs_info.json");
    let package_commit = if vcs.exists() {
        println!("cargo::rerun-if-changed={}", vcs.display());
        let metadata: serde_json::Value = serde_json::from_slice(&fs::read(vcs)?)?;
        metadata
            .get("git")
            .and_then(|git| git.get("sha1"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    } else {
        None
    };

    built::write_built_file()?;
    let mut output = fs::OpenOptions::new()
        .append(true)
        .open(PathBuf::from(env::var("OUT_DIR")?).join("built.rs"))?;
    writeln!(
        output,
        "pub const PACKAGE_COMMIT_HASH: Option<&str> = {package_commit:?};"
    )?;
    Ok(())
}
