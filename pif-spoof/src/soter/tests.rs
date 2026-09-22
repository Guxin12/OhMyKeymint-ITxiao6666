use super::{wire::Writer, *};

#[derive(Default)]
struct Buffer(Vec<u8>);

impl Buffer {
    fn align(&mut self) {
        self.0.resize((self.0.len() + 3) & !3, 0);
    }
}

impl Writer for Buffer {
    fn int32(&mut self, value: i32) -> Result<(), i32> {
        self.0.extend_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn int64(&mut self, value: i64) -> Result<(), i32> {
        self.0.extend_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), i32> {
        self.int32(value.len() as i32)?;
        self.0.extend_from_slice(value);
        self.align();
        Ok(())
    }

    fn string(&mut self, value: &str) -> Result<(), i32> {
        self.int32(value.encode_utf16().count() as i32)?;
        for unit in value.encode_utf16().chain([0]) {
            self.0.extend_from_slice(&unit.to_le_bytes());
        }
        self.align();
        Ok(())
    }
}

fn request(code: u32) -> Vec<u8> {
    let mut output = Buffer::default();
    output.int32(0x8000_0000u32 as i32).unwrap();
    output.int32(-1).unwrap();
    output.int32(0x5359_5354).unwrap();
    output.string(DESCRIPTOR.to_str().unwrap()).unwrap();
    match code {
        1..=3 | 7 => output.int32(10001).unwrap(),
        4..=6 | 8 => {
            output.int32(10001).unwrap();
            output.string("key").unwrap();
        }
        9 => {
            output.int32(10001).unwrap();
            output.string("key").unwrap();
            output.string("challenge").unwrap();
        }
        10 => output.int64(123).unwrap(),
        13 => output.string("type").unwrap(),
        _ => {}
    }
    output.0
}

fn transaction(code: u32, bytes: &[u8]) -> Transaction {
    Transaction {
        target: 0x1234,
        cookie: 0x5678,
        code,
        flags: 0x10,
        sender_pid: 42,
        sender_euid: 10001,
        data_size: bytes.len() as u64,
        buffer: bytes.as_ptr() as u64,
        ..Default::default()
    }
}

#[test]
fn accepts_exact_supported_aidl_requests_and_rejects_every_truncation() {
    for code in 1..=13 {
        let bytes = request(code);
        assert!(wire::valid_request(code, &bytes), "code {code}");
        for length in 0..bytes.len() {
            assert!(
                !wire::valid_request(code, &bytes[..length]),
                "code {code} length {length}"
            );
        }
        let mut trailing = bytes;
        trailing.extend_from_slice(&[0; 4]);
        assert!(!wire::valid_request(code, &trailing));
    }
    for code in [0, 14, u32::MAX] {
        assert!(!wire::valid_request(code, &request(code)));
    }
}

#[test]
fn rejects_token_substrings_header_variants_and_invalid_string_lengths() {
    let valid = request(12);
    for index in [8, 12, 16, 17, 16 + DESCRIPTOR.to_bytes().len() * 2] {
        let mut bytes = valid.clone();
        bytes[index] ^= 1;
        assert!(!wire::valid_request(12, &bytes), "byte {index}");
    }
    let mut absent_header = valid[12..].to_vec();
    assert!(!wire::valid_request(12, &absent_header));
    absent_header.splice(0..0, [0; 32]);
    assert!(!wire::valid_request(12, &absent_header));
    for length in [-2, -1, i32::MAX] {
        let mut bytes = valid.clone();
        bytes[12..16].copy_from_slice(&length.to_le_bytes());
        assert!(!wire::valid_request(12, &bytes));
    }
    let mut larger = valid.clone();
    larger.resize(MAX_REQUEST_BYTES + 4, 0);
    assert!(!wire::valid_request(12, &larger));
}

#[test]
fn accepts_nullable_arguments_but_not_invalid_or_incomplete_strings() {
    let prefix = request(12);
    let mut null = prefix.clone();
    null.extend_from_slice(&(-1i32).to_le_bytes());
    assert!(wire::valid_request(13, &null));
    for count in [-2, 0, 1, i32::MAX] {
        let mut bytes = prefix.clone();
        bytes.extend_from_slice(&count.to_le_bytes());
        assert!(!wire::valid_request(13, &bytes));
    }
    let mut unicode = Buffer(prefix);
    unicode.string("\u{1f600}\u{4e2d}").unwrap();
    assert!(wire::valid_request(13, &unicode.0));
}

#[test]
fn preserves_all_transaction_fields_except_selected_target() {
    let destination = Target {
        ptr: 0x8000,
        cookie: 0x9000,
    };
    for code in 1..=13 {
        let bytes = request(code);
        let before = transaction(code, &bytes);
        let mut after = before;
        retarget(&mut after, &bytes, destination);
        assert_eq!(
            after,
            Transaction {
                target: destination.ptr,
                cookie: destination.cookie,
                ..before
            }
        );
    }
}

#[test]
fn leaves_unrelated_unsupported_or_malformed_transactions_unchanged() {
    let bytes = request(3);
    let base = transaction(3, &bytes);
    for before in [
        Transaction { target: 0, ..base },
        Transaction { cookie: 0, ..base },
        Transaction { flags: 1, ..base },
        Transaction { flags: 8, ..base },
        Transaction {
            flags: 0x40,
            ..base
        },
        Transaction { code: 14, ..base },
        Transaction { code: 10, ..base },
        Transaction {
            offsets_size: 8,
            ..base
        },
        Transaction {
            data_size: MAX_REQUEST_BYTES as u64 + 1,
            ..base
        },
        Transaction { buffer: 0, ..base },
        Transaction {
            buffer: u64::MAX,
            ..base
        },
        Transaction {
            data_size: base.data_size - 1,
            ..base
        },
    ] {
        let mut after = before;
        retarget(&mut after, &bytes, Target { ptr: 1, cookie: 2 });
        assert_eq!(after, before);
    }
    let mut malformed = bytes.clone();
    malformed[16] ^= 1;
    let mut after = base;
    retarget(&mut after, &malformed, Target { ptr: 1, cookie: 2 });
    assert_eq!(after, base);
}

fn append_command(buffer: &mut Vec<u8>, command: u32, transaction: Transaction) {
    buffer.extend_from_slice(&command.to_ne_bytes());
    let data = unsafe {
        std::slice::from_raw_parts(
            (&transaction as *const Transaction).cast::<u8>(),
            size_of::<Transaction>(),
        )
    };
    buffer.extend_from_slice(data);
    if command == BR_TRANSACTION_SEC_CTX {
        buffer.extend_from_slice(&0x1234u64.to_ne_bytes());
    }
}

#[test]
fn validates_full_command_buffer_before_visiting_and_handles_secctx() {
    assert_eq!(size_of::<Transaction>(), 64);
    assert_eq!(size_of::<WriteRead>(), 48);
    let mut commands = Vec::new();
    append_command(
        &mut commands,
        BR_TRANSACTION,
        Transaction {
            code: 2,
            ..Default::default()
        },
    );
    commands.extend_from_slice(&0x720cu32.to_ne_bytes()); // BR_NOOP
    append_command(
        &mut commands,
        BR_TRANSACTION_SEC_CTX,
        Transaction {
            code: 6,
            ..Default::default()
        },
    );
    assert!(valid_read_commands(&commands));
    let mut visited = Vec::new();
    visit_transactions(&mut commands, |transaction| {
        visited.push(transaction.code);
        transaction.target = 0x8888;
    });
    assert_eq!(visited, [2, 6]);
    assert_eq!(&commands[commands.len() - 8..], &0x1234u64.to_ne_bytes());
    for length in 1..68 {
        assert!(!valid_read_commands(&commands[..length]));
    }
    let complete = commands.len();
    for extra in 1..4 {
        commands.resize(complete + extra, 0);
        assert!(!valid_read_commands(&commands));
    }
    assert!(!valid_pointer_range(u64::MAX - 2, 4));
    assert!(!valid_pointer_range(0, 1));
}

#[test]
fn only_exact_transaction_commands_are_visited() {
    for command in [0x8040_7203u32, 0x8038_7202, 0x4040_7202, 0x8040_6302] {
        let mut bytes = command.to_ne_bytes().to_vec();
        bytes.resize(4 + ((command >> 16) & 0x3fff) as usize, 0);
        assert!(valid_read_commands(&bytes));
        visit_transactions(&mut bytes, |_| panic!("unrelated command was visited"));
    }
}

#[test]
fn rejects_invalid_binder_carriers() {
    let mut carrier = vec![0; 28];
    carrier[..4].copy_from_slice(&BINDER_TYPE_BINDER.to_ne_bytes());
    carrier[8..16].copy_from_slice(&0x1000u64.to_ne_bytes());
    carrier[16..24].copy_from_slice(&0x2000u64.to_ne_bytes());
    assert_eq!(
        parse_carrier(&carrier),
        Some(Target {
            ptr: 0x1000,
            cookie: 0x2000
        })
    );
    for length in 0..28 {
        assert!(parse_carrier(&carrier[..length]).is_none());
    }
    carrier[0] ^= 1;
    assert!(parse_carrier(&carrier).is_none());
    carrier[0] ^= 1;
    carrier[8..16].fill(0);
    assert!(parse_carrier(&carrier).is_none());
}

fn int32(bytes: &[u8], position: usize) -> i32 {
    i32::from_le_bytes(bytes[position..position + 4].try_into().unwrap())
}

#[test]
fn encodes_all_d_soter_reply_shapes_without_session_queues() {
    for code in 1..=13 {
        let mut output = Buffer::default();
        wire::write_reply(code, &mut output).unwrap();
        let bytes = output.0;
        assert_eq!(int32(&bytes, 0), 0);
        match code {
            1 | 4 | 5 | 7 => assert_eq!(bytes, [0; 8]),
            3 | 8 | 12 => assert_eq!(bytes, [0, 0, 0, 0, 1, 0, 0, 0]),
            2 | 6 | 10 | 11 => {
                assert_eq!(int32(&bytes, 4), 1);
                assert_eq!(int32(&bytes, 8), 0);
                let length = int32(&bytes, 12) as usize;
                let padded = (length + 3) & !3;
                assert_eq!(int32(&bytes, 16 + padded), length as i32);
                assert_eq!(bytes.len(), 20 + padded);
                let payload = &bytes[16..16 + length];
                match code {
                    2 | 6 => {
                        let json_length = int32(payload, 0) as usize;
                        assert_eq!(payload.len(), 4 + json_length + 256);
                        let json = std::str::from_utf8(&payload[4..4 + json_length]).unwrap();
                        assert!(json.starts_with("{\"pub_key\":\""));
                        assert!(json.ends_with("\"uid\":0}"));
                        assert!(payload[4 + json_length..].iter().all(|byte| *byte == 0));
                    }
                    10 => assert_eq!(payload, [0; 256]),
                    11 => assert_eq!(payload, b"TEESIM-SOTER-0001"),
                    _ => unreachable!(),
                }
            }
            9 => {
                assert_eq!(bytes.len(), 20);
                assert_eq!(int32(&bytes, 4), 1);
                assert_eq!(i64::from_le_bytes(bytes[8..16].try_into().unwrap()), 1);
                assert_eq!(int32(&bytes, 16), 0);
            }
            13 => {
                let mut expected = Buffer::default();
                for value in [0, 1, 0] {
                    expected.int32(value).unwrap();
                }
                expected.string("optical").unwrap();
                assert_eq!(bytes, expected.0);
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn stops_on_native_write_errors_and_rejects_unknown_codes_without_output() {
    struct Reject;
    impl Writer for Reject {
        fn int32(&mut self, _: i32) -> Result<(), i32> {
            Err(-12)
        }
        fn int64(&mut self, _: i64) -> Result<(), i32> {
            panic!("write after failure")
        }
        fn bytes(&mut self, _: &[u8]) -> Result<(), i32> {
            panic!("write after failure")
        }
        fn string(&mut self, _: &str) -> Result<(), i32> {
            panic!("write after failure")
        }
    }
    for code in 1..=13 {
        assert_eq!(wire::write_reply(code, &mut Reject), Err(-12));
    }
    for code in [0, 14, u32::MAX] {
        let mut output = Buffer::default();
        assert_eq!(
            wire::write_reply(code, &mut output),
            Err(UNKNOWN_TRANSACTION)
        );
        assert!(output.0.is_empty());
    }
}
