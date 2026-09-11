use copyfail_rs::CopyFail;

const CMSG_TOTAL: usize = 88;

#[test]
fn cmsg_buffer_layout_matches_c_reference() {
    let mut buf = [0u8; CMSG_TOTAL];
    CopyFail::build_cmsg(&mut buf);

    // cmsg 1: ALG_SET_OP — len=20, level=279 (SOL_ALG), type=3 (ALG_SET_OP), payload u32=0 (ALG_OP_DECRYPT)
    assert_eq!(read_usize(&buf, 0), 20, "cmsg 1 len");
    assert_eq!(read_i32(&buf, 8), 279, "cmsg 1 SOL_ALG");
    assert_eq!(read_i32(&buf, 12), 3, "cmsg 1 ALG_SET_OP");
    assert_eq!(read_u32(&buf, 16), 0, "cmsg 1 payload ALG_OP_DECRYPT");

    // cmsg 2: ALG_SET_IV — at offset 24; len=36, level=279, type=2, payload {ivlen=16, iv=zero[16]}
    let off2 = 24;
    assert_eq!(read_usize(&buf, off2), 36, "cmsg 2 len");
    assert_eq!(read_i32(&buf, off2 + 8), 279, "cmsg 2 SOL_ALG");
    assert_eq!(read_i32(&buf, off2 + 12), 2, "cmsg 2 ALG_SET_IV");
    assert_eq!(read_u32(&buf, off2 + 16), 16, "cmsg 2 ivlen");
    for i in 0..16 {
        assert_eq!(buf[off2 + 20 + i], 0, "cmsg 2 IV byte {} should be zero", i);
    }

    // cmsg 3: ALG_SET_AEAD_ASSOCLEN — at offset 24+40=64; len=20, level=279, type=4, payload u32=8
    let off3 = 64;
    assert_eq!(read_usize(&buf, off3), 20, "cmsg 3 len");
    assert_eq!(read_i32(&buf, off3 + 8), 279, "cmsg 3 SOL_ALG");
    assert_eq!(read_i32(&buf, off3 + 12), 4, "cmsg 3 ALG_SET_AEAD_ASSOCLEN");
    assert_eq!(read_u32(&buf, off3 + 16), 8, "cmsg 3 AAD len");
}

#[test]
#[allow(non_snake_case)]
fn data_buffer_is_AAAA_plus_chunk() {
    let mut data = [0u8; 8];
    let chunk = [0xDE, 0xAD, 0xBE, 0xEF];
    CopyFail::build_data(&chunk, &mut data);
    assert_eq!(&data[..4], b"AAAA");
    assert_eq!(&data[4..], &chunk);
}

fn read_usize(b: &[u8], o: usize) -> usize {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    usize::from_ne_bytes(a)
}

fn read_i32(b: &[u8], o: usize) -> i32 {
    let mut a = [0u8; 4];
    a.copy_from_slice(&b[o..o + 4]);
    i32::from_ne_bytes(a)
}

fn read_u32(b: &[u8], o: usize) -> u32 {
    let mut a = [0u8; 4];
    a.copy_from_slice(&b[o..o + 4]);
    u32::from_ne_bytes(a)
}
