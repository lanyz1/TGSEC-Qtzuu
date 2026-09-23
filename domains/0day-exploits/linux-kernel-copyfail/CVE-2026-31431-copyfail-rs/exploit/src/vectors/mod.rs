pub mod pam;
pub mod passwd;
pub mod payload;
pub mod su;

use crate::Vector;

pub fn select(name: &[u8]) -> Option<&'static dyn Vector> {
    match name {
        b"su" => Some(&su::SuVector),
        b"passwd" => Some(&passwd::PasswdVector),
        _ => None,
    }
}
