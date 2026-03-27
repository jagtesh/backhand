//! Storage of directories with references to inodes
//!
//! For each directory inode, the directory table stores a linear list of all entries,
//! with references back to the inodes that describe those entries.

use std::ffi::OsStr;
use std::path::{Component, Path};

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
    /// Return the filename component of this directory entry as a `Path`.
    ///
    /// # Upstream fix (this fork)
    ///
    /// The original implementation validated the filename using `Path::file_name()`:
    ///
    /// ```rust,ignore
    /// let path = Path::new(OsStr::from_bytes(&self.name));
    /// let filename = path.file_name().map(OsStrExt::as_bytes);
    /// if filename != Some(&self.name) { ... }
    /// ```
    ///
    /// This is correct on Linux, but fails on Windows because the `Path` type is
    /// host-OS-aware: on Windows, `\` is treated as a directory separator, so a
    /// Linux filename like `systemd\x2dmute.slice` (a real file inside Ubuntu's
    /// SquashFS image) is interpreted as a two-component Windows path and
    /// `file_name()` returns only the last component — causing the validation to
    /// fail with `BackhandError::InvalidFilePath` even though the filename is
    /// perfectly valid by SquashFS and POSIX rules.
    ///
    /// The fix: validate using **raw byte rules** that mirror the SquashFS spec,
    /// with no host-OS path interpretation at all:
    /// - `/` is only valid when the entry is the root
    /// - NUL bytes are never valid in filenames
    /// - `.` and `..` are not valid directory entry names in SquashFS
    ///
    /// This approach is consistent with how the Linux kernel and tools like
    /// `unsquashfs` validate SquashFS directory entries.
    ///
    /// # Windows display names (PUA mapping — application concern)
    ///
    /// On Windows, characters like `\`, `:`, `*`, `?`, `"`, `<`, `>`, `|` and
    /// control characters are illegal in filesystem names (Win32 API restriction).
    /// A SquashFS image from a Linux system may legally contain these characters.
    ///
    /// **This mapping is intentionally NOT performed here.** It is an
    /// application-level display concern, not a parsing concern. The consuming
    /// application (e.g. squashbox-core) is responsible for remapping characters
    /// when building a Windows-visible directory index. This mirrors the approach
    /// taken by WSL2: the Windows Subsystem for Linux maps Linux-illegal-on-Windows
    /// filenames to Unicode Private Use Area (PUA) codepoints in the range
    /// U+F000–U+F0FF when surfacing them via the Windows filesystem API, keeping
    /// round-trip fidelity without polluting the parser layer with display policy.
    ///
    /// # Return type
    ///
    /// Returns `&Path` (a zero-copy view into `self.name`) on all platforms. On
    /// Windows this is safe as long as the caller does not pass the result to any
    /// Win32 filesystem API directly — which it should not, since this is a parsed
    /// in-memory representation of a SquashFS entry, not a host filesystem path.
    pub fn name(&self) -> Result<&Path, BackhandError> {
        // Allow root and nothing else as a rooted path
        if self.name == Component::RootDir.as_os_str().as_bytes() {
            return Ok(Path::new(Component::RootDir.as_os_str()));
        }

        // Validate using raw byte rules — no host-OS Path interpretation.
        //
        // This is the key fix: the original code used Path::file_name() which
        // on Windows treats `\` as a path separator, incorrectly rejecting valid
        // Linux filenames. We instead check only the properties that SquashFS
        // itself prohibits.
        if self.name.is_empty()
            || self.name.contains(&b'/')
            || self.name.contains(&b'\0')
            || self.name == b"."
            || self.name == b".."
        {
            return Err(BackhandError::InvalidFilePath);
        }

        // Zero-copy: construct a Path view directly over the raw bytes.
        // On Linux/macOS this is lossless. On Windows, Path will interpret the
        // bytes as a WTF-8 string; since we have already verified there are no
        // `/` or `\0` bytes, this is safe for in-memory use. The caller must NOT
        // pass this path to a Win32 filesystem API — the consuming application
        // is responsible for PUA-mapping Windows-illegal characters before
        // creating any OS-visible names.
        Ok(Path::new(OsStr::from_bytes(&self.name)))
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
