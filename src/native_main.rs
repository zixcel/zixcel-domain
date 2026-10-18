fn main() -> std::process::ExitCode {
    zix_native_provider::serve(
        zixcel_domain::native::manifest(),
        zixcel_domain::native::execute,
    )
}
