use anyhow::Result;
use www::{
    cli::{actions::Action, commands, dispatch},
    tls::TlsMode,
};

#[test]
fn version_flags_distinguish_package_version_and_full_commit() -> Result<()> {
    let short = std::process::Command::new(env!("CARGO_BIN_EXE_www"))
        .arg("-V")
        .output()?;
    assert!(short.status.success());
    assert_eq!(short.stderr.as_slice(), b"");
    let version = format!("www {}", env!("CARGO_PKG_VERSION"));
    assert_eq!(String::from_utf8(short.stdout)?.trim(), version);

    let long = std::process::Command::new(env!("CARGO_BIN_EXE_www"))
        .arg("--version")
        .output()?;
    assert!(long.status.success());
    assert_eq!(long.stderr.as_slice(), b"");
    let output = String::from_utf8(long.stdout)?;
    let hash = output
        .trim()
        .strip_prefix(&format!("{version} - "))
        .ok_or_else(|| anyhow::anyhow!("long version has no commit hash: {output}"))?;
    assert!(hash == "unknown" || (hash.len() == 40 && hash.bytes().all(|b| b.is_ascii_hexdigit())));
    Ok(())
}

#[test]
fn defaults_and_flags() -> Result<()> {
    let matches = commands::new().try_get_matches_from(["www"])?;
    let Action::Serve(config) = dispatch::handler(&matches)? else {
        anyhow::bail!("expected default listener action");
    };
    assert_eq!(config.root.to_str(), Some("."));
    assert_eq!(config.port, 8000);
    assert!(matches!(config.tls, TlsMode::Http));

    let matches = commands::new().try_get_matches_from([
        "www",
        "-p",
        "8080",
        "-r",
        "/tmp",
        "-q",
        "-s",
        "localhost",
    ])?;
    let Action::Serve(config) = dispatch::handler(&matches)? else {
        anyhow::bail!("expected default listener action");
    };
    assert_eq!(config.root.to_str(), Some("/tmp"));
    assert_eq!(config.port, 8080);
    assert!(matches!(config.tls, TlsMode::Localhost));
    assert!(matches.get_flag("quiet"));
    Ok(())
}

#[test]
fn domain_forces_port_and_uses_persistent_storage() -> Result<()> {
    let matches =
        commands::new().try_get_matches_from(["www", "-s", "EXAMPLE.COM", "-p", "8080"])?;
    let Action::Serve(config) = dispatch::handler(&matches)? else {
        anyhow::bail!("expected default listener action");
    };
    assert_eq!(config.port, 443);
    let TlsMode::Acme(options) = config.tls else {
        anyhow::bail!("expected ACME")
    };
    assert_eq!(options.domain, "example.com");
    assert!(
        options.cache_dir.ends_with("www/acme") || options.cache_dir.ends_with("io.nbari.www/acme")
    );
    assert!(!options.staging);
    Ok(())
}

#[test]
fn explicit_cache_and_staging() -> Result<()> {
    let matches = commands::new().try_get_matches_from([
        "www",
        "-s",
        "example.com",
        "--cert-cache",
        "/custom/cache",
        "--acme-staging",
    ])?;
    let Action::Serve(config) = dispatch::handler(&matches)? else {
        anyhow::bail!("expected default listener action");
    };
    let TlsMode::Acme(options) = config.tls else {
        anyhow::bail!("expected ACME")
    };
    assert_eq!(options.cache_dir.to_str(), Some("/custom/cache"));
    assert!(options.staging);
    Ok(())
}

#[test]
fn canonicalize_domains_for_direct_server_callers() -> Result<()> {
    assert_eq!(www::tls::normalize_domain("EXAMPLE.COM")?, "example.com");
    for domain in ["localhost.", "example.com.", "_bad.example.com"] {
        assert!(www::tls::normalize_domain(domain).is_err());
    }
    Ok(())
}

#[test]
fn reject_invalid_arguments_and_domain_combinations() -> Result<()> {
    for args in [
        vec!["www", "-p", "65536"],
        vec!["www", "-p", "-1"],
        vec!["www", "--acme-staging"],
        vec!["www", "--unknown"],
        vec!["www", "unexpected"],
    ] {
        assert!(commands::new().try_get_matches_from(args).is_err());
    }
    for domain in [
        "https://example.com",
        "*.example.com",
        "127.0.0.1",
        "example.com:443",
        "bad name.com",
        "localhost.",
        "example.com.",
        "_bad.example.com",
    ] {
        let matches = commands::new().try_get_matches_from(["www", "-s", domain])?;
        assert!(dispatch::handler(&matches).is_err(), "accepted {domain}");
    }
    for domain in ["localhost", ""] {
        let matches =
            commands::new().try_get_matches_from(["www", "-s", domain, "--acme-staging"])?;
        assert!(dispatch::handler(&matches).is_err());
    }
    Ok(())
}

#[test]
fn bind_parses_numeric_addresses_and_preserves_port_rules() -> Result<()> {
    for address in ["127.0.0.1", "0.0.0.0", "::1", "::"] {
        let matches =
            commands::new().try_get_matches_from(["www", "--bind", address, "-p", "8080"])?;
        let Action::ServeBound(config, parsed) = dispatch::handler(&matches)? else {
            anyhow::bail!("expected explicit listener action");
        };
        assert_eq!(parsed, address.parse::<std::net::IpAddr>()?);
        assert_eq!(config.port, 8080);
        assert!(matches!(config.tls, TlsMode::Http));
    }
    for (domain, expected_port) in [("localhost", 8080), ("example.com", 443)] {
        let matches = commands::new().try_get_matches_from([
            "www",
            "--bind",
            "127.0.0.1",
            "-p",
            "8080",
            "-s",
            domain,
        ])?;
        let Action::ServeBound(config, _) = dispatch::handler(&matches)? else {
            anyhow::bail!("expected explicit listener action");
        };
        assert_eq!(config.port, expected_port);
    }
    for address in [
        "localhost",
        "example.com",
        "127.0.0.1:8080",
        "[::1]:8080",
        "[::1]",
        "999.1.1.1",
    ] {
        assert!(
            commands::new()
                .try_get_matches_from(["www", "--bind", address])
                .is_err()
        );
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_www"))
            .args(["--bind", address])
            .output()?;
        assert!(!output.status.success());
        assert!(String::from_utf8(output.stderr)?.contains("--bind"));
    }
    Ok(())
}
