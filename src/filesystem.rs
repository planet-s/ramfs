use std::collections::BTreeMap;
use std::os::unix::io::AsRawFd;
use std::fs;

use syscall::{Error, Result, StatVfs, TimeSpec};
use syscall::error::EIO;
use syscall::flag::{O_RDONLY, O_STAT};

pub struct File {
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub ino: usize,
    pub nlink: usize,

    pub atime: TimeSpec,
    pub ctime: TimeSpec,
    pub mtime: TimeSpec,
    pub crtime: TimeSpec,

    pub data: FileData,
}

pub enum FileData {
    File(Vec<u8>),
    Directory(Vec<Vec<u8>>),
}
impl FileData {
    pub fn size(&self) -> usize {
        match self {
            &Self::File(ref data) => data.len(),
            &Self::Directory(ref names) => names.iter().map(|name| name.len()).sum(),
        }
    }
}

pub struct Filesystem {
    pub files: BTreeMap<usize, File>,
    pub tree: BTreeMap<Vec<u8>, usize>,
    pub memory_file: fs::File,
}
impl Filesystem {
    pub const DEFAULT_BLOCK_SIZE: u32 = 4096;

    pub fn new() -> Result<Self> {
        Ok(Self {
            files: BTreeMap::new(),
            tree: BTreeMap::new(),
            memory_file: fs::File::open("memory:").or(Err(Error::new(EIO)))?,
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
    pub fn resolve(&self, mut path: &[u8], uid: u32, gid: u32) -> Option<usize> {
        // TODO: CoW
        let mut path = path.to_owned();
        // TODO: Replace follow symlinks, and replace double slashes with single slashes.

        // TODO: Check that every directory in the path grant the user the search permission.
        self.tree.get(&path).copied()
    }
}
