use std::ops::{Deref, DerefMut};

use compact_str::CompactString;


pub struct CompactStr(pub CompactString);

impl CompactStr {
    pub fn new() -> Self {
        Self(CompactString::new(""))
    }
}

impl std::fmt::Display for CompactStr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.as_str())
    }
}

impl std::io::Write for CompactStr {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let s = unsafe { std::str::from_utf8_unchecked(buf) };
        self.0.push_str(s);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl std::fmt::Write for CompactStr {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.0.push_str(s);
        Ok(())
    }
}

impl From<&str> for CompactStr {
    fn from(s: &str) -> Self {
        Self(CompactString::from(s))
    }
}

impl From<String> for CompactStr {
    fn from(s: String) -> Self {
        Self(CompactString::from(s))
    }
}

impl From<CompactString> for CompactStr {
    fn from(s: CompactString) -> Self {
        Self(s)
    }
}

impl Deref for CompactStr {
    type Target = CompactString;
    fn deref(&self) -> &CompactString {
        &self.0
    }
}

impl DerefMut for CompactStr {
    fn deref_mut(&mut self) -> &mut CompactString {
        &mut self.0
    }
}
