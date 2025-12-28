fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cert = rcgen::generate_simple_self_signed(["paniq".into()])?;
    let cert_der = cert.serialize_der()?;
    let key_der = cert.serialize_private_key_der();

    std::fs::write("bin/test_cert.der", cert_der)?;
    std::fs::write("bin/test_key.der", key_der)?;

    println!("Generated bin/test_cert.der and bin/test_key.der");
    Ok(())
}
