use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;

use std::os::unix::io::AsRawFd;
use std::os::unix::ffi::OsStrExt;

use bstr::ByteSlice;

use syscall::{Error, Result, StatVfs, TimeSpec};
use syscall::error::{EACCES, EIO, ENFILE, ENOENT};
use syscall::flag::{O_RDONLY, O_STAT};

use super::scheme::current_perm;

pub struct File {
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub ino: usize,
    pub nlink: usize,

    pub open_handles: usize,

    pub atime: TimeSpec,
    pub ctime: TimeSpec,
    pub mtime: TimeSpec,
    pub crtime: TimeSpec,

    pub data: FileData,
}

pub struct DirEntry {
    pub name: Vec<u8>,
    pub inode: usize,
}

pub enum FileData {
    File(Vec<u8>),
    Directory(Vec<DirEntry>),
}
impl FileData {
    pub fn size(&self) -> usize {
        match self {
            &Self::File(ref data) => data.len(),
            &Self::Directory(ref names) => names.iter().map(|dentry| dentry.name.len()).sum(),
        }
    }
    pub fn as_directory(&self) -> Option<&[DirEntry]> {
        match self {
            &Self::Directory(ref inner) => Some(inner),
            _ => None,
        }
    }
    pub fn as_directory_mut(&mut self) -> Option<&mut Vec<DirEntry>> {
        match self {
            &mut Self::Directory(ref mut inner) => Some(inner),
            _ => None,
        }
    }
}

pub struct Filesystem {
    pub files: BTreeMap<usize, File>,
    pub memory_file: fs::File,
    pub last_inode_number: usize,
}
impl Filesystem {
    pub const DEFAULT_BLOCK_SIZE: u32 = 4096;
    pub const ROOT_INODE: usize = 1;

    pub fn new() -> Result<Self> {
        Ok(Self {
            files: BTreeMap::new(),
            memory_file: fs::File::open("memory:").or(Err(Error::new(EIO)))?,
            last_inode_number: Self::ROOT_INODE,
        })
    }
    pub fn get_block_size(&self) -> Result<u32> {
        let mut statvfs = StatVfs::default();
        syscall::fstatvfs(self.memory_file.as_raw_fd() as usize, &mut statvfs)?;
        Ok(statvfs.f_bsize)
    }
    pub fn block_size(&self) -> u32 {
        self.get_block_size().unwrap_or(Self::DEFAULT_BLOCK_SIZE)
    }
    pub fn next_inode_number(&mut self) -> Result<usize> {
        let next = self.last_inode_number.checked_add(1).ok_or(Error::new(ENFILE))?;
        self.last_inode_number = next;
        Ok(next)
    }
    fn resolve_generic(&self, parts: Vec<&[u8]>, uid: u32, gid: u32) -> Result<usize> {
        let mut current_file = self.files.get(&Self::ROOT_INODE).ok_or(Error::new(ENOENT))?;
        let mut current_inode = Self::ROOT_INODE;

        let mut i = 0;

        while let Some(part) = parts.get(i) {
            let dentries = match current_file.data {
                FileData::Directory(ref dentries) => dentries,
                FileData::File(_) => return Err(Error::new(ENOENT)),
            };
            let perm = current_perm(&current_file, uid, gid);
            if perm & 0o1 == 0 { return Err(Error::new(EACCES)) }

            if part == b"." || part == b".." {
                parts.remove(i);
            }
            if part == b".." {
                if i > 0 {
                    i -= 1;
                    parts.remove(i);
                }
            }

            let entry = dentries.iter().find(|dentry| &dentry.name == part).ok_or(Error::new(ENOENT))?;
            current_file = self.files.get(&entry.inode).ok_or(Error::new(EIO))?;
            current_inode = entry.inode;

            i += 1;
        }
        Ok(current_inode)
    }
    pub fn resolve_except_last<'a>(&self, mut path_bytes: &'a [u8], uid: u32, gid: u32) -> Result<(usize, &'a [u8])> {
        if path_bytes.first() == Some(&b'/') { path_bytes = &path_bytes[1..] }
        let parts = path_components_iter(path_bytes).collect::<Vec<_>>();
        let last = parts.pop().ok_or(Error::new(ENOENT))?;

        Ok((self.resolve_generic(parts, uid, gid)?, last))
    }
    pub fn resolve(&self, mut path_bytes: &[u8], uid: u32, gid: u32) -> Result<usize> {
        if path_bytes.first() == Some(&b'/') { path_bytes = &path_bytes[1..] }
        let parts = path_components_iter(path_bytes).collect::<Vec<_>>();

        self.resolve_generic(parts, uid, gid)
    }
}
pub fn path_components_iter(bytes: &[u8]) -> impl Iterator<Item = &[u8]> + '_ {
    let components_iter = bytes.split(|c| c == &b'/');
    components_iter.filter(|item| !item.is_empty())
}
