#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let reply = local_dpi_bypass::cli::dispatch(&borrowed);
    if reply.code == 0 {
        println!("{}", reply.text);
    } else {
        eprintln!("{}", reply.text);
    }
    std::process::ExitCode::from(reply.code)
}
