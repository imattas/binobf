use std::ffi::{c_char, c_void, CStr, CString};
use std::fmt;

#[repr(C)]
struct RawError {
    struct_size: u32,
    code: *mut c_char,
    code_capacity: usize,
    message: *mut c_char,
    message_capacity: usize,
}

#[repr(C)]
struct RawDetection {
    struct_size: u32,
    format: u32,
    kind: u32,
    architecture: u32,
    entry_point: u64,
}

#[link(name = "binobf_c")]
unsafe extern "C" {
    fn binobf_version() -> *const c_char;
    fn binobf_detect(
        bytes: *const c_void,
        size: usize,
        source_name: *const c_char,
        output: *mut RawDetection,
        error: *mut RawError,
    ) -> i32;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Detection {
    pub format: u32,
    pub kind: u32,
    pub architecture: u32,
    pub entry_point: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    pub status: i32,
    pub code: String,
    pub message: String,
}

impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for Error {}

pub fn version() -> &'static CStr {
    unsafe { CStr::from_ptr(binobf_version()) }
}

pub fn detect(bytes: &[u8], source_name: &str) -> Result<Detection, Error> {
    let source = CString::new(source_name).map_err(|_| Error {
        status: 1,
        code: "rust.invalid_argument".to_owned(),
        message: "source_name contains an interior NUL".to_owned(),
    })?;
    let mut code = vec![0 as c_char; 128];
    let mut message = vec![0 as c_char; 512];
    let mut error = RawError {
        struct_size: std::mem::size_of::<RawError>() as u32,
        code: code.as_mut_ptr(),
        code_capacity: code.len(),
        message: message.as_mut_ptr(),
        message_capacity: message.len(),
    };
    let mut output = RawDetection {
        struct_size: std::mem::size_of::<RawDetection>() as u32,
        format: 0,
        kind: 0,
        architecture: 0,
        entry_point: 0,
    };
    let status = unsafe {
        binobf_detect(
            bytes.as_ptr().cast(),
            bytes.len(),
            source.as_ptr(),
            &mut output,
            &mut error,
        )
    };
    if status != 0 {
        let code = unsafe { CStr::from_ptr(error.code) }.to_string_lossy().into_owned();
        let message = unsafe { CStr::from_ptr(error.message) }.to_string_lossy().into_owned();
        return Err(Error { status, code, message });
    }
    Ok(Detection {
        format: output.format,
        kind: output.kind,
        architecture: output.architecture,
        entry_point: output.entry_point,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_minimal_elf() {
        let mut bytes = [0u8; 64];
        bytes[0..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[16..18].copy_from_slice(&1u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        let detection = detect(&bytes, "rust-fixture.o").expect("detection succeeds");
        assert_eq!((detection.format, detection.kind, detection.architecture), (2, 3, 1));
    }
}
