use super::*;

#[test]
fn bytes_obf_matches_input() {
    let obf = BytesObf::new("0a0b0c").expect("parse bytes obf");
    let mut dst = vec![0u8; obf.obfuscated_len(0)];
    obf.obfuscate(&mut dst, &[]);
    assert_eq!(dst, vec![0x0a, 0x0b, 0x0c]);
    assert!(obf.deobfuscate(&mut [], &dst));
}

#[test]
fn chain_obfuscates_in_order() {
    let chain = parse_chain("<b 0x0102><dz 2><d>").expect("chain");
    let payload = b"AB";
    let mut dst = vec![0u8; chain.obfuscated_len(payload.len())];
    chain.obfuscate(&mut dst, payload);
    let mut decoded = vec![0u8; chain.deobfuscated_len(dst.len())];
    assert!(chain.deobfuscate(&mut decoded, &dst));
    assert_eq!(decoded, payload);
}

#[test]
fn header_range_validates() {
    let header = parse_header("1-3").expect("parse header");
    assert!(header.validate(1));
    assert!(header.validate(3));
    assert!(!header.validate(4));
    assert_eq!(header.gen_spec(), "1-3");
}

#[test]
fn framer_round_trip() {
    let cfg = Config {
        jc: 0,
        jmin: 0,
        jmax: 0,
        s1: 0,
        s2: 0,
        s3: 0,
        s4: 0,
        h1: "10".into(),
        h2: "20".into(),
        h3: "30".into(),
        h4: "40".into(),
        i1: "<b 0x01><d>".into(),
        i2: String::new(),
        i3: String::new(),
        i4: String::new(),
        i5: String::new(),
    };
    let framer = Framer::new(cfg).expect("framer");
    let payload = b"hello";
    let frame = framer
        .encode_frame(MessageType::Initiation, payload)
        .expect("encode");
    let (msg_type, decoded) = framer.decode_frame(&frame).expect("decode");
    assert_eq!(msg_type, MessageType::Initiation);
    assert_eq!(decoded, payload);
}

#[test]
fn deterministic_rng_outputs() {
    let rng = SharedRng::from_seed(42);
    let obf = RandObf::new("4", rng).unwrap();
    let mut dst1 = vec![0u8; 4];
    obf.obfuscate(&mut dst1, &[]);

    let rng2 = SharedRng::from_seed(42);
    let obf2 = RandObf::new("4", rng2).unwrap();
    let mut dst2 = vec![0u8; 4];
    obf2.obfuscate(&mut dst2, &[]);

    assert_eq!(dst1, dst2);
}

#[test]
fn framer_rng_can_be_seeded() {
    let cfg = Config {
        jc: 2,
        jmin: 4,
        jmax: 4,
        s1: 2,
        s2: 0,
        s3: 0,
        s4: 0,
        h1: "1-3".into(),
        h2: "10".into(),
        h3: "20".into(),
        h4: "30".into(),
        i1: "<r 2>".into(),
        i2: String::new(),
        i3: String::new(),
        i4: String::new(),
        i5: String::new(),
    };

    let framer_one = Framer::new_with_rng(cfg.clone(), SharedRng::from_seed(7)).unwrap();
    let framer_two = Framer::new_with_rng(cfg, SharedRng::from_seed(7)).unwrap();

    let frame_one = framer_one
        .encode_frame(MessageType::Initiation, b"hi")
        .unwrap();
    let frame_two = framer_two
        .encode_frame(MessageType::Initiation, b"hi")
        .unwrap();
    assert_eq!(frame_one, frame_two);

    let junk_one = framer_one.junk_datagrams().unwrap();
    let junk_two = framer_two.junk_datagrams().unwrap();
    assert_eq!(junk_one, junk_two);

    let sig_one = framer_one.signature_datagrams().unwrap();
    let sig_two = framer_two.signature_datagrams().unwrap();
    assert_eq!(sig_one, sig_two);
}
