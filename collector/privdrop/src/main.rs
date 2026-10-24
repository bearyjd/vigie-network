fn main() {
    if let Err(error) = vigie_privdrop::run() {
        eprintln!("vigie-privdrop: {error}");
        std::process::exit(77);
    }
}
