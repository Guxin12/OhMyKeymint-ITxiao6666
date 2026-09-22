use std::sync::OnceLock;

use super::{BAD_VALUE, DESCRIPTOR, MAX_REQUEST_BYTES, UNKNOWN_TRANSACTION};

const SYSTEM_HEADER: u32 = 0x5359_5354;
const SIGNATURE: [u8; 256] = [0; 256];
const DEVICE: &[u8] = b"TEESIM-SOTER-0001";
// D-Soter's public placeholder, not a private key or a device identity.
const EXPORT_JSON: &str = concat!(
    "{\"pub_key\":\"",
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw8gEMK6J6jBvJr1b9K8j",
    "o4jMHF5D4BoHYXTsRov+v+clqEwXntTeXrOcQeuQX9Fys5S3Jmbs6safW1vmbJps",
    "k8Qe7wbi9p1v9uh3JzmF3j2Mw+tXtGI9h/1Vm1n6T3GrQJQ+tvuQ+vN8n6kMYl64",
    "J7CuyYw6P5vl6Z4WlfhdY5oJc0Q9T6xVwK6bg3DOjFEq5k1DTXJZuzqjONyYCuuP",
    "v7TTuLT8yT0+9m+CF7i65DKQJE3Ak0dCj0Ar1sIH7yLPlvWv85ExKYOvCXLdB6t8",
    "eWg0/eeoPHDLLv11Oyq9JR0gDk0iHT5SWG2FHKY5xIb3C2we8O7CVOaPwIDAQAB",
    "\",\"counter\":0,\"cpu_id\":\"0000000000000000\",\"uid\":0}"
);

fn export_blob() -> &'static [u8] {
    static BLOB: OnceLock<Vec<u8>> = OnceLock::new();
    BLOB.get_or_init(|| {
        let mut bytes = Vec::with_capacity(4 + EXPORT_JSON.len() + SIGNATURE.len());
        bytes.extend_from_slice(&(EXPORT_JSON.len() as u32).to_le_bytes());
        bytes.extend_from_slice(EXPORT_JSON.as_bytes());
        bytes.extend_from_slice(&SIGNATURE);
        bytes
    })
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let end = self.position.checked_add(count)?;
        let bytes = self.bytes.get(self.position..end)?;
        self.position = end;
        Some(bytes)
    }

    fn int32(&mut self) -> Option<i32> {
        Some(i32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn string(&mut self) -> Option<Option<&'a [u8]>> {
        let count = self.int32()?;
        if count == -1 {
            return Some(None);
        }
        let count = usize::try_from(count).ok()?.checked_mul(2)?;
        let value = self.take(count)?;
        if self.take(2)? != [0, 0] {
            return None;
        }
        self.take((4 - (self.position % 4)) % 4)?;
        Some(Some(value))
    }
}

pub(super) fn valid_request(code: u32, bytes: &[u8]) -> bool {
    if bytes.len() > MAX_REQUEST_BYTES || !bytes.len().is_multiple_of(4) {
        return false;
    }
    let mut reader = Reader { bytes, position: 0 };
    let valid = (|| {
        reader.take(8)?; // strict-mode policy and propagated work-source UID
        if reader.int32()? as u32 != SYSTEM_HEADER {
            return None;
        }
        let token = reader.string()??;
        let expected = DESCRIPTOR.to_bytes();
        if token.len() != expected.len() * 2
            || !token
                .as_chunks::<2>()
                .0
                .iter()
                .zip(expected)
                .all(|(unit, byte)| *unit == [*byte, 0])
        {
            return None;
        }
        match code {
            1..=3 | 7 => {
                reader.int32()?;
            }
            4..=6 | 8 => {
                reader.int32()?;
                reader.string()?;
            }
            9 => {
                reader.int32()?;
                reader.string()?;
                reader.string()?;
            }
            10 => {
                reader.take(8)?;
            }
            11 | 12 => {}
            13 => {
                reader.string()?;
            }
            _ => return None,
        }
        (reader.position == bytes.len()).then_some(())
    })();
    valid.is_some()
}

pub(super) trait Writer {
    fn int32(&mut self, value: i32) -> Result<(), i32>;
    fn int64(&mut self, value: i64) -> Result<(), i32>;
    fn bytes(&mut self, value: &[u8]) -> Result<(), i32>;
    fn string(&mut self, value: &str) -> Result<(), i32>;
}

pub(super) fn write_reply(code: u32, output: &mut impl Writer) -> Result<(), i32> {
    if !(1..=13).contains(&code) {
        return Err(UNKNOWN_TRANSACTION);
    }
    output.int32(0)?; // Java Parcel.writeNoException()
    match code {
        1 | 4 | 5 | 7 => output.int32(0),
        3 | 8 | 12 => output.int32(1),
        2 | 6 | 10 | 11 => {
            let bytes = match code {
                2 | 6 => export_blob(),
                10 => &SIGNATURE,
                11 => DEVICE,
                _ => return Err(BAD_VALUE),
            };
            output.int32(1)?;
            output.int32(0)?;
            output.bytes(bytes)?;
            output.int32(bytes.len() as i32)
        }
        9 => {
            output.int32(1)?;
            output.int64(1)?;
            output.int32(0)
        }
        13 => {
            output.int32(1)?;
            output.int32(0)?; // Parcel.writeValue() VAL_STRING
            output.string("optical")
        }
        _ => Err(UNKNOWN_TRANSACTION),
    }
}
