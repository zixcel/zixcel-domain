fn main() -> std::process::ExitCode {
    zix_native_provider::serve(zixcel_domain_cli::manifest(), zixcel_domain_cli::execute)
}
