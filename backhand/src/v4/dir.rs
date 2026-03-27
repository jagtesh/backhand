//! Storage of directories with references to inodes
//!
//! For each directory inode, the directory table stores a linear list of all entries,
//! with references back to the inodes that describe those entries.

#[allow(unused_imports)]
use std::ffi::OsStr;
use std::path::{Component, PathBuf};

use deku::prelude::*;

use crate::error::BackhandError;
use crate::v4::inode::InodeId;
use crate::v4::unix_string::OsStrExt;

#[derive(Debug, DekuRead, DekuWrite, Clone, PartialEq, Eq)]
#[deku(ctx = "type_endian: deku::ctx::Endian")]
#[deku(endian = "type_endian")]
pub struct Dir {
    /// Number of entries following the header.
    ///
    /// A header must be followed by AT MOST 256 entries. If there are more entries, a new header MUST be emitted.
    #[deku(assert = "*count <= 256")]
    pub(crate) count: u32,
    /// The location of the metadata block in the inode table where the inodes are stored.
    /// This is relative to the inode table start from the super block.
    pub(crate) start: u32,
    /// An arbitrary inode number.
    /// The entries that follow store their inode number as a difference to this.
    pub(crate) inode_num: u32,
    #[deku(count = "*count + 1")]
    pub(crate) dir_entries: Vec<DirEntry>,
}

impl Dir {
    pub fn new(lowest_inode: u32) -> Self {
        Self {
            count: u32::default(),
            start: u32::default(),
            inode_num: lowest_inode,
            dir_entries: vec![],
        }
    }

    pub fn push(&mut self, entry: DirEntry) {
        self.dir_entries.push(entry);
        self.count = (self.dir_entries.len() - 1) as u32;
    }
}

#[derive(Debug, DekuRead, DekuWrite, Clone, PartialEq, Eq)]
#[deku(endian = "endian", ctx = "endian: deku::ctx::Endian")]
pub struct DirEntry {
    /// An offset into the uncompressed inode metadata block.
    pub(crate) offset: u16,
    /// The difference of this inode's number to the reference stored in the header.
    pub(crate) inode_offset: i16,
    /// The inode type. For extended inodes, the basic type is stored here instead.
    pub(crate) t: InodeId,
    /// One less than the size of the entry name.
    pub(crate) name_size: u16,
    // TODO: CString
    /// The file name of the entry without a trailing null byte. Has name size + 1 bytes.
    #[deku(count = "*name_size + 1")]
    pub(crate) name: Vec<u8>,
}

impl DirEntry {
    /// Return the filename component of this directory entry as a path.
    ///
    /// # Cross-platform filename handling
    ///
    /// SquashFS is a Linux-native format. Linux filenames can legally contain
    /// characters that Windows treats specially — most critically, the backslash
    /// `\` which Windows `Path` interprets as a directory separator.
    ///
    /// ## Why PUA mapping is required (not optional)
    ///
    /// backhand internally uses `PathBuf::push(entry.name()?)` / `pop()` in
    /// `extract_dir()` to build the full path tree. If a filename contains a
    /// literal `\` (common in Ubuntu SquashFS images — e.g. systemd unit names
    /// like `systemd\x2dmute.slice`), on Windows:
    ///
    /// 1. `push` interprets `\` as a path separator → adds **two** components
    /// 2. `pop` removes only **one** component
    /// 3. The fullpath drifts, mis-parenting all subsequent entries
    ///
    /// This corrupts the entire directory tree, causing entries from deep
    /// subdirectories to appear at the root level.
    ///
    /// ## The fix: WSL2-style PUA mapping
    ///
    /// On Windows, all characters illegal in Win32 filenames (`\`, `:`, `*`,
    /// `?`, `"`, `<`, `>`, `|`, and control chars 0x00–0x1F) are mapped to
    /// their Unicode Private Use Area (PUA) equivalents in U+F000–U+F0FF.
    ///
    /// This is the same strategy used by WSL2 (Windows Subsystem for Linux)
    /// when surfacing Linux-native filenames through the Windows filesystem
    /// API. The mapping is:
    /// - Lossless: each illegal byte maps to a unique PUA codepoint
    /// - Round-trippable: U+F05C always means "this was a Linux backslash"
    /// - Safe for PathBuf: PUA codepoints are not path separators
    ///
    /// References:
    /// - WSL filesystem interop: https://learn.microsoft.com/en-us/windows/wsl/filesystems
    /// - PUA range U+F000–U+F0FF in Unicode: https://www.unicode.org/charts/PDF/UF000.pdf
    ///
    /// ## Validation
    ///
    /// The original upstream code used `Path::file_name()` for validation,
    /// which is host-OS-aware and fails on Windows for the same reason.
    /// We validate using raw byte rules matching the SquashFS specification:
    /// - `/` (forward slash) is only valid as the root entry
    /// - NUL bytes are never valid
    /// - `.` and `..` are not valid directory entry names
    ///
    /// ## Return type
    ///
    /// Returns `PathBuf` on all platforms. On Unix this is a minor allocation
    /// (one per entry during image parsing). On Windows, the owned `PathBuf`
    /// is required because we construct a new string with PUA codepoints.
    pub fn name(&self) -> Result<PathBuf, BackhandError> {
        // Allow root and nothing else as a rooted path
        if self.name == Component::RootDir.as_os_str().as_bytes() {
            return Ok(PathBuf::from(Component::RootDir.as_os_str()));
        }

        // Validate using raw byte rules — no host-OS Path interpretation.
        if self.name.is_empty()
            || self.name.contains(&b'/')
            || self.name.contains(&b'\0')
            || self.name == b"."
            || self.name == b".."
        {
            return Err(BackhandError::InvalidFilePath);
        }

        // On Windows: map characters illegal in Win32 filenames to Unicode
        // Private Use Area codepoints (WSL2-compatible mapping).
        // This is required for correctness, not just display — see doc comment.
        #[cfg(windows)]
        {
            let mut s = String::with_capacity(self.name.len());
            for &b in &self.name {
                match b {
                    b'\\' => s.push('\u{F05C}'), // backslash → PUA (CRITICAL: prevents PathBuf corruption)
                    b':'  => s.push('\u{F03A}'),
                    b'*'  => s.push('\u{F02A}'),
                    b'?'  => s.push('\u{F03F}'),
                    b'"'  => s.push('\u{F022}'),
                    b'<'  => s.push('\u{F03C}'),
                    b'>'  => s.push('\u{F03E}'),
                    b'|'  => s.push('\u{F07C}'),
                    c if c < 0x20 => s.push(
                        char::from_u32(0xF000 + c as u32).unwrap_or('\u{FFFD}')
                    ),
                    _ => s.push(b as char),
                }
            }
            return Ok(PathBuf::from(s));
        }

        // On Unix: zero-copy path from raw bytes. All POSIX-legal bytes are
        // valid filename characters (only `/` and NUL are forbidden, already
        // checked above).
        #[cfg(not(windows))]
        {
            Ok(PathBuf::from(OsStr::from_bytes(&self.name)))
        }
    }
}



#[derive(Debug, DekuRead, DekuWrite, Clone, PartialEq, Eq)]
#[deku(endian = "endian", ctx = "endian: deku::ctx::Endian")]
pub struct DirectoryIndex {
    /// This stores a byte offset from the first directory header to the current header,
    /// as if the uncompressed directory metadata blocks were laid out in memory consecutively.
    pub(crate) index: u32,
    /// Start offset of a directory table metadata block, relative to the directory table start.
    pub(crate) start: u32,
    #[deku(assert = "*name_size < 256")]
    pub(crate) name_size: u32,
    #[deku(count = "*name_size + 1")]
    pub(crate) name: Vec<u8>,
}

impl DirectoryIndex {
    pub fn name(&self) -> String {
        core::str::from_utf8(&self.name).unwrap().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_invalid_dir_entry() {
        // just root
        let dir = DirEntry {
            offset: 0x300,
            inode_offset: 0x0,
            t: InodeId::BasicDirectory,
            name_size: 0x1,
            name: b"/".to_vec(),
        };
        assert_eq!(PathBuf::from("/"), dir.name().unwrap());

        // InvalidFilePath
        let dir = DirEntry {
            offset: 0x300,
            inode_offset: 0x0,
            t: InodeId::BasicDirectory,
            name_size: 0x1,
            name: b"/nice/".to_vec(),
        };
        assert!(dir.name().is_err());
    }
}
