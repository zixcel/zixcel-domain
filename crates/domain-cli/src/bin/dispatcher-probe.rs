//! Development-only executable for testing the real common CLI dispatcher.
fn main() -> std::process::ExitCode {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    match runtime.block_on(zix_cli::command_line::run(
        &std::env::args().skip(1).collect::<Vec<_>>(),
    )) {
        Ok(true) => std::process::ExitCode::SUCCESS,
        Ok(false) => std::process::ExitCode::from(1),
        Err(e) => {
            eprintln!("{{\"error\":\"{}\"}}", e.0);
            std::process::ExitCode::from(2)
        }
    }
}
