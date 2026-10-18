fn main() -> std::process::ExitCode {
    zix_native_provider::bundle::main(
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_REPOSITORY"),
    )
}
