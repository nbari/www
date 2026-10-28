use www::cli::{self, actions::Action};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let result = async {
        match cli::start()? {
            Action::Serve(config) => cli::actions::serve::execute(config).await,
            Action::ServeBound(config, address) => {
                cli::actions::serve::execute_bound(config, address).await
            }
        }
    }
    .await;

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("www: {error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
