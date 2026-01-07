//! Example of using the FFI binding to decode a CBOR profile.
//!
//! To run this example:
//! cargo run --example ffi_usage --features mobile

#[cfg(feature = "mobile")]
fn main() {
    use paniq::ffi::decode_profile_to_json;

    // This is a sample base64-encoded CBOR profile.
    // In a real mobile app, this would come from a pnq:// deep link.
    // This sample was generated using:
    // ./target/debug/paniq-ctl create-profile --proxy-addr my-server:9000 | ./target/debug/paniq-ctl profile-cbor --base64
    let sample_b64_cbor = "qAABAW1iZi0yMDI2LTAxLTA3Am5teS1zZXJ2ZXI6OTAwMAUFBgUHogEZBYwCGQSwCLQBAwIZAjMDGQR2BBkBMAUZASYGGQEuBxgqCHUxNzY1OTA2NTkxLTE3NjU5MDc1OTAJdTI2MDY1MzE2NjctMjYwNjUzMjY2Ngp1MzIzNDg3MDcyNC0zMjM0ODcxNzIzC3U0MTQzNzYxMDgwLTQxNDM3NjIwNzkMYzx0PhFYILyuGEwb0iWlVznSA5UaIffn6mEJD70ypJwqSSgtDHuaElggUDCkuq7UXF+burBuDWXCLxCx8sBPuwvAb8LA1jwRSAsT9RT1FfUW9RggGDIYIRQJoQQYgA==";

    println!("Decoding sample Base64 CBOR profile...");

    match decode_profile_to_json(sample_b64_cbor.to_string()) {
        Ok(json) => {
            println!("Successfully decoded profile to JSON:");
            println!("{}", json);
        }
        Err(e) => {
            eprintln!("Failed to decode profile: {:?}", e);
        }
    }
}

#[cfg(not(feature = "mobile"))]
fn main() {
    println!("This example requires the 'mobile' feature.");
    println!("Run with: cargo run --example ffi_usage --features mobile");
}
