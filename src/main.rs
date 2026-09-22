use rustnies::cli;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match cli::run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "rustnies terminated with an error");
            eprintln!("rustnies: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
