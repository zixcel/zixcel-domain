fn main() -> std::process::ExitCode {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 1 {
        eprintln!("usage_output_directory");
        return std::process::ExitCode::from(2);
    }
    let output = std::path::Path::new(&arguments[0]);
    let result = std::fs::create_dir_all(output)
        .map_err(|_| "output_unavailable")
        .and_then(|()| zix_native_provider::bundle::collect_notices(output));
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(code) => {
            eprintln!("{code}");
            std::process::ExitCode::from(2)
        }
    }
}
