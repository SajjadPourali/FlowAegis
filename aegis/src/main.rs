fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ebpf"
    )))?;
    println!("Hello, world!");
    Ok(())
}
