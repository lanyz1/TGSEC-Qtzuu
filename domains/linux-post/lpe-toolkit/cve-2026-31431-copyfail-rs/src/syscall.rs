use crate::Error;

#[inline]
pub fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

#[inline]
pub fn last() -> Error {
    Error::Syscall(errno())
}

#[inline]
pub unsafe fn close_fd(fd: i32) {
    if fd >= 0 {
        libc::close(fd);
    }
}
