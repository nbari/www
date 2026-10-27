//! Stream build-time HTTPS downloads through Rustls, including FreeBSD sysroots.

use anyhow::{Context, Result, bail};
use std::{path::PathBuf, time::Duration};
use tokio::io::AsyncWriteExt;

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let url = args
        .next()
        .context("usage: fetch HTTPS_URL OUTPUT")?
        .into_string()
        .map_err(|_| anyhow::anyhow!("URL must be UTF-8"))?;
    let output = PathBuf::from(args.next().context("missing output path")?);
    if args.next().is_some() {
        bail!("usage: fetch HTTPS_URL OUTPUT");
    }
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let temporary = tempfile::NamedTempFile::new_in(parent)?;
    let mut file = tokio::fs::File::from_std(temporary.reopen()?);
    let client = reqwest::Client::builder()
        .https_only(true)
        .timeout(Duration::from_secs(300))
        .build()?;
    let mut response = client.get(url).send().await?.error_for_status()?;
    while let Some(chunk) = response.chunk().await? {
        file.write_all(&chunk).await?;
    }
    file.flush().await?;
    file.sync_all().await?;
    drop(file);
    temporary.persist(output)?;
    Ok(())
}
