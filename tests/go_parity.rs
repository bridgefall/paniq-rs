use std::path::PathBuf;
use std::process::Command;

use hex::encode;
use paniq::obf::parse_chain;

#[test]
fn go_rust_chain_parity_smoke() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir.parent().expect("repo root");

    let cases = [
        ("<b 0x0102><d>", b"hello".as_ref()),
        ("<d>", b"paniq".as_ref()),
        ("<b 0x01><dz 2><d>", b"abcd".as_ref()),
    ];

    for (spec, input) in cases {
        let chain = parse_chain(spec).expect("parse rust chain");
        let mut rust_out = vec![0u8; chain.obfuscated_len(input.len())];
        chain.obfuscate(&mut rust_out, input);

        let go_output = Command::new("go")
            .args([
                "run",
                "./cmd/obf-vector",
                "--spec",
                spec,
                "--input",
                &encode(input),
            ])
            .current_dir(repo_root)
            .output()
            .expect("spawn go run");

        assert!(
            go_output.status.success(),
            "go run failed: {}",
            String::from_utf8_lossy(&go_output.stderr)
        );

        let go_hex = String::from_utf8_lossy(&go_output.stdout)
            .trim()
            .to_string();
        assert_eq!(encode(&rust_out), go_hex, "go and rust outputs diverged");

        let mut decoded = vec![0u8; chain.deobfuscated_len(rust_out.len())];
        assert!(chain.deobfuscate(&mut decoded, &rust_out));
        assert_eq!(input, &decoded[..input.len()]);
    }
}
