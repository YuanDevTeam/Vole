#[path = "../cli.rs"]
mod cli;

#[cfg(target_os = "linux")]
#[global_allocator]
static CLI_ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> std::process::ExitCode {
    cli::entry()
}
