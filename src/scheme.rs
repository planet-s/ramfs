use std::collections::BTreeMap;
use std::convert::{TryFrom, TryInto};
use std::os::unix::io::AsRawFd;
use std::{cmp, ops};

use syscall::{Error, EventFlags, Map, Result, SchemeMut, Stat, StatVfs, TimeSpec};
use syscall::flag::{O_RDWR, O_RDONLY, O_WRONLY, O_DIRECTORY, O_STAT};
use syscall::{MODE_DIR, MODE_PERM, MODE_TYPE, SEEK_CUR, SEEK_END, SEEK_SET};
use syscall::error::{EACCES, EBADF, EBADFD, EFBIG, EINVAL, EISDIR, ENOENT, ENOMEM, ENOSYS, ENOTDIR, EOPNOTSUPP, EOVERFLOW};

use crate::filesystem::{FileData, Filesystem};

#[derive(Clone)]
struct Handle {
    inode: usize,
    offset: usize,
}

pub struct Scheme {
    scheme_name: String,
    handles: BTreeMap<usize, Handle>,
    next_fd: usize,
    filesystem: Filesystem,
}
impl Scheme {
    pub fn new(scheme_name: String) -> Result<Self> {
        Ok(Self {
            scheme_name,
            handles: BTreeMap::new(),
            filesystem: Filesystem::new()?,
            next_fd: 0,
        })
    }
}

impl SchemeMut for Scheme {
    fn open(&mut self, path: &[u8], flags: usize, uid: u32, gid: u32) -> Result<usize> {
        let inode = self.filesystem.resolve(path, uid, gid).ok_or(Error::new(ENOENT))?;
        let file = self.filesystem.files.get(&inode).ok_or(Error::new(ENOENT))?;

        if flags & O_STAT == 0 && flags & O_DIRECTORY != 0 && file.mode & MODE_TYPE != MODE_DIR {
            return Err(Error::new(ENOTDIR));
        }
        if flags & O_STAT == 0 && flags & O_DIRECTORY == 0 && file.mode & MODE_TYPE == MODE_DIR {
            return Err(Error::new(EISDIR));
        }

        let perm = file.mode & MODE_PERM;
        
        if uid == file.uid {
            check_permissions(flags, (perm & 0o700) >> 6)?;
        } else if gid == file.gid {
            check_permissions(flags, (perm & 0o70) >> 3)?;
        } else {
            check_permissions(flags, perm & 0o7)?;
        }

        let handle = Handle {
            inode,
            offset: 0,
        };

        let fd = self.next_fd;
        self.next_fd += 1;

        self.handles.insert(fd, handle);

        Ok(fd)
    }
    fn chmod(&mut self, path: &[u8], mode: u16, uid: u32, gid: u32) -> Result<usize> {
        // TODO
        Err(Error::new(ENOSYS))
    }
    fn rmdir(&mut self, path: &[u8], uid: u32, gid: u32) -> Result<usize> {
        // TODO
        Err(Error::new(ENOSYS))
    }
    fn unlink(&mut self, path: &[u8], uid: u32, gid: u32) -> Result<usize> {
        // TODO
        Err(Error::new(ENOSYS))
    }
    fn dup(&mut self, old_fd: usize, _buf: &[u8]) -> Result<usize> {
        let handle = self.handles.get_mut(&old_fd).ok_or(Error::new(EBADF))?.clone();

        let fd = self.next_fd;
        self.next_fd += 1;

        self.handles.insert(fd, handle);
        Ok(fd)
    }
    fn read(&mut self, fd: usize, buf: &mut [u8]) -> Result<usize> {
        let handle = self.handles.get_mut(&fd).ok_or(Error::new(EBADF))?;
        let file = self.filesystem.files.get_mut(&handle.inode).ok_or(Error::new(EBADFD))?;

        match file.data {
            FileData::File(ref bytes) => {
                if file.mode & MODE_TYPE == MODE_DIR { return Err(Error::new(EBADFD)) }
                if handle.offset >= bytes.len() {
                    return Ok(0);
                }
                let bytes_to_read = cmp::min(bytes.len(), buf.len() + handle.offset) - handle.offset;
                buf[..bytes_to_read].copy_from_slice(&bytes[handle.offset..handle.offset + bytes_to_read]);
                Ok(bytes_to_read)
            }
            FileData::Directory(ref entries) => {
                if file.mode & MODE_TYPE != MODE_DIR { return Err(Error::new(EBADFD)) }

                let mut bytes_to_skip = handle.offset;
                let mut bytes_left_to_read = buf.len();
                let mut bytes_read = 0;

                for entry_bytes in entries {
                    // skip the whole entry if it fits
                    if bytes_to_skip >= entry_bytes.len() {
                        bytes_to_skip -= entry_bytes.len();
                        continue;
                    }

                    let bytes_to_read = cmp::min(entry_bytes.len() - bytes_to_skip, bytes_left_to_read);

                    let entry_bytes = &entry_bytes[bytes_to_skip..bytes_to_skip + bytes_to_read];
                    bytes_to_skip -= bytes_to_skip;

                    buf[handle.offset..handle.offset + bytes_to_read].copy_from_slice(&entry_bytes[..bytes_to_read]);
                    bytes_left_to_read -= bytes_to_read;
                    bytes_read += bytes_to_read;
                }
                Ok(bytes_read)
            }
        }
    }
    fn write(&mut self, fd: usize, buf: &[u8]) -> Result<usize> {
        let handle = self.handles.get_mut(&fd).ok_or(Error::new(EBADF))?;
        let file = self.filesystem.files.get_mut(&handle.inode).ok_or(Error::new(EBADFD))?;

        if let &mut FileData::File(ref mut bytes) = &mut file.data {
            if file.mode & MODE_TYPE == MODE_DIR { return Err(Error::new(EBADFD)) }

            // if there's a seek hole, fill it with 0 and continue writing.
            if handle.offset > bytes.len() {
                let additional = handle.offset - bytes.len();
                bytes.try_reserve(additional).or(Err(Error::new(ENOMEM)))?;
                bytes.resize(handle.offset, 0u8);
            }
            bytes.extend(buf);
            Ok(buf.len())
        } else {
            Err(Error::new(EISDIR))
        }
    }
    fn seek(&mut self, fd: usize, pos: usize, whence: usize) -> Result<usize> {
        let handle = self.handles.get_mut(&fd).ok_or(Error::new(EBADF))?;
        let file = self.filesystem.files.get_mut(&handle.inode).ok_or(Error::new(EBADFD))?;

        // cast to isize, possibly making the offset negative
        let pos = pos as isize;

        handle.offset = match whence {
            SEEK_SET => cmp::max(0, pos) as usize,
            SEEK_CUR => cmp::max(0, pos + isize::try_from(handle.offset).or(Err(Error::new(EOVERFLOW)))?) as usize,
            SEEK_END => cmp::max(0, pos + isize::try_from(file.data.size()).or(Err(Error::new(EOVERFLOW)))?) as usize,
            _ => return Err(Error::new(EINVAL)),
        };
        Ok(handle.offset)
    }
    fn fchmod(&mut self, fd: usize, mode: u16) -> Result<usize> {
        let handle = self.handles.get_mut(&fd).ok_or(Error::new(EBADF))?;
        let file = self.filesystem.files.get_mut(&handle.inode).ok_or(Error::new(EBADFD))?;

        // TODO: Check that no file becomes a directory etc.
        file.mode = mode;

        Ok(0)
    }
    fn fchown(&mut self, fd: usize, uid: u32, gid: u32) -> Result<usize> {
        let handle = self.handles.get_mut(&fd).ok_or(Error::new(EBADF))?;
        let file = self.filesystem.files.get_mut(&handle.inode).ok_or(Error::new(EBADFD))?;

        file.uid = uid;
        file.gid = gid;

        Ok(0)
    }
    fn fcntl(&mut self, fd: usize, _cmd: usize, _arg: usize) -> Result<usize> {
        if ! self.handles.contains_key(&fd) {
            return Err(Error::new(EBADF));
        }
        Ok(0)
    }
    fn fevent(&mut self, fd: usize, _flags: EventFlags) -> Result<EventFlags> {
        if ! self.handles.contains_key(&fd) {
            return Err(Error::new(EBADF));
        }
        Err(Error::new(ENOSYS))
    }
    fn fmap(&mut self, fd: usize, _map: &Map) -> Result<usize> {
        if ! self.handles.contains_key(&fd) {
            return Err(Error::new(EBADF));
        }
        // TODO
        Err(Error::new(ENOSYS))
    }
    fn funmap(&mut self, _address: usize) -> Result<usize> {
        // TODO
        Err(Error::new(ENOSYS))
    }
    fn fpath(&mut self, fd: usize, buf: &mut [u8]) -> Result<usize> {
        if ! self.handles.contains_key(&fd) {
            return Err(Error::new(EBADF));
        }
        // TODO
        Err(Error::new(ENOSYS))
    }
    fn frename(&mut self, fd: usize, path: &[u8], uid: u32, gid: u32) -> Result<usize> {
        if ! self.handles.contains_key(&fd) {
            return Err(Error::new(EBADF));
        }
        // TODO
        Err(Error::new(ENOSYS))
    }
    fn fstat(&mut self, fd: usize, stat: &mut Stat) -> Result<usize> {
        let handle = self.handles.get_mut(&fd).ok_or(Error::new(EBADF))?;
        let block_size = self.filesystem.block_size();
        let file = self.filesystem.files.get_mut(&handle.inode).ok_or(Error::new(EBADFD))?;

        *stat = Stat {
            st_mode: file.mode,
            st_uid: file.uid,
            st_gid: file.gid,
            st_ino: handle.inode.try_into().or(Err(Error::new(EOVERFLOW)))?,
            st_nlink: file.nlink.try_into().or(Err(Error::new(EOVERFLOW)))?,
            st_dev: 0,

            st_size: file.data.size().try_into().or(Err(Error::new(EOVERFLOW)))?,
            st_blksize: block_size,
            st_blocks: div_round_up(stat.st_size, u64::from(stat.st_blksize)),

            st_atime: file.atime.tv_sec.try_into().or(Err(Error::new(EOVERFLOW)))?,
            st_atime_nsec: file.atime.tv_nsec.try_into().or(Err(Error::new(EOVERFLOW)))?,

            st_ctime: file.ctime.tv_sec.try_into().or(Err(Error::new(EOVERFLOW)))?,
            st_ctime_nsec: file.ctime.tv_nsec.try_into().or(Err(Error::new(EOVERFLOW)))?,

            st_mtime: file.mtime.tv_sec.try_into().or(Err(Error::new(EOVERFLOW)))?,
            st_mtime_nsec: file.mtime.tv_nsec.try_into().or(Err(Error::new(EOVERFLOW)))?,
        };

        Ok(0)
    }
    fn fstatvfs(&mut self, fd: usize, stat: &mut StatVfs) -> Result<usize> {
        if ! self.handles.contains_key(&fd) {
            return Err(Error::new(EBADF));
        }
        syscall::fstatvfs(self.filesystem.memory_file.as_raw_fd() as usize, stat)?;

        Ok(0)
    }
    fn fsync(&mut self, fd: usize) -> Result<usize> {
        if ! self.handles.contains_key(&fd) {
            return Err(Error::new(EBADF));
        }
        Ok(0)
    }
    fn ftruncate(&mut self, fd: usize, size: usize) -> Result<usize> {
        let handle = self.handles.get_mut(&fd).ok_or(Error::new(EBADF))?;
        let file = self.filesystem.files.get_mut(&handle.inode).ok_or(Error::new(EBADFD))?;

        if file.mode & MODE_TYPE == MODE_DIR {
            return Err(Error::new(EISDIR));
        }
        match &mut file.data {
            &mut FileData::File(ref mut bytes) => {
                if size > bytes.len() {
                    let additional = size - bytes.len();
                    bytes.try_reserve(additional).or(Err(Error::new(ENOMEM)))?;
                    bytes.resize(size, 0u8)
                } else {
                    bytes.resize(size, 0u8)
                }
            }
            &mut FileData::Directory(_) => return Err(Error::new(EBADFD)),
        }
        Ok(0)
    }
    fn futimens(&mut self, fd: usize, times: &[TimeSpec]) -> Result<usize> {
        let handle = self.handles.get_mut(&fd).ok_or(Error::new(EBADF))?;
        let file = self.filesystem.files.get_mut(&handle.inode).ok_or(Error::new(EBADFD))?;

        let new_atime = *times.get(0).ok_or(Error::new(EINVAL))?;
        let new_mtime = *times.get(1).ok_or(Error::new(EINVAL))?;

        file.atime = new_atime;
        file.mtime = new_mtime;

        Ok(0)
    }
    fn close(&mut self, fd: usize) -> Result<usize> {
        if self.handles.remove(&fd).is_none() {
            return Err(Error::new(EBADF));
        }
        Ok(0)
    }
}
fn div_round_up<T>(numer: T, denom: T) -> T
where
    T: Copy + ops::Add<T, Output = T> + ops::Sub<T, Output = T> + ops::Div<T, Output = T> + From<u8>,
{
    (numer + (denom - T::from(1u8))) / denom
}
fn check_permissions(flags: usize, single_mode: u16) -> Result<()> {
    if flags & O_RDWR == O_RDONLY && single_mode & 0o4 == 0 {
        return Err(Error::new(EACCES));
    } else if flags & O_RDWR == O_WRONLY && single_mode & 0o2 == 0 {
        return Err(Error::new(EACCES));
    } else if flags & O_RDWR == O_RDWR && single_mode & 0o6 != 0o6 {
        return Err(Error::new(EACCES));
    }
    Ok(())
}
