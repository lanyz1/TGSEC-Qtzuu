#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* 验证 b 指令编码：offset = (delta >> 2) & 0x3FFFFFF */
uint32_t enc_b(long delta) {
    if (delta > 0x7FFFFFC || delta < -0x8000000) return 0;
    return 0x14000000u | ((uint32_t)((delta >> 2) & 0x03FFFFFFu));
}
long dec_b(uint32_t insn) {
    int32_t imm26 = insn & 0x03FFFFFFu;
    /* 符号扩展 26 位 */
    if (imm26 & 0x02000000) imm26 |= (int32_t)0xFC000000;
    return (long)imm26 << 2;
}

/* 验证 16 字节块：ldr x16,#8 ; br x16 */
void enc_abs_block(void *dest, unsigned char out[16]) {
    out[0]=0x50; out[1]=0x00; out[2]=0x00; out[3]=0x58;  /* ldr x16,#8 */
    out[4]=0x00; out[5]=0x02; out[6]=0x1F; out[7]=0xD6;  /* br x16 */
    uint64_t d=(uint64_t)dest;
    for(int i=0;i<8;i++) out[8+i]=(unsigned char)((d>>(i*8))&0xff);
}

int main(){
    long tests[] = {0, 4, 8, -4, -8, 0x1000, -0x1000, 0x7FFFFC, -0x8000000, 0x123454};
    int pass=0, fail=0;
    printf("%-12s %-12s %-12s %s\n","delta","encoded","decoded","结果");
    for (unsigned i=0;i<sizeof(tests)/sizeof(tests[0]);i++){
        long d=tests[i];
        uint32_t e=enc_b(d); long r=dec_b(e);
        int ok=(r==d);
        printf("%-12ld 0x%-10x %-12ld %s\n", d, e, r, ok?"OK":"FAIL");
        ok?pass++:fail++;
    }
    /* 验证 16 字节块解析 */
    printf("\n=== 16 字节绝对跳转块验证 ===\n");
    unsigned char blk[16];
    enc_abs_block((void*)0x74dbc4730cu, blk);   /* 真实的 Cronet_CertVerify_DoVerifyV2 地址 */
    printf("bytes: ");
    for(int i=0;i<16;i++) printf("%02x ",blk[i]);
    printf("\n");
    uint32_t i0 = blk[0]|(blk[1]<<8)|(blk[2]<<16)|(blk[3]<<24);
    uint32_t i1 = blk[4]|(blk[5]<<8)|(blk[6]<<16)|(blk[7]<<24);
    uint64_t addr=0; for(int i=0;i<8;i++) addr |= ((uint64_t)blk[8+i])<<(i*8);
    printf("insn0=0x%08x (期望 0x58000050 = ldr x16,#8) %s\n", i0, i0==0x58000050?"OK":"FAIL");
    printf("insn1=0x%08x (期望 0xd61f0200 = br x16)    %s\n", i1, i1==0xD61F0200?"OK":"FAIL");
    printf("dest =0x%lx (期望 0x74dbc4730c)            %s\n", addr, addr==0x74dbc4730cul?"OK":"FAIL");
    if(i0==0x58000050&&i1==0xD61F0200&&addr==0x74dbc4730cul) pass+=3; else fail+=3;
    printf("\n结果: %d 通过, %d 失败\n", pass, fail);
    return fail?1:0;
}
