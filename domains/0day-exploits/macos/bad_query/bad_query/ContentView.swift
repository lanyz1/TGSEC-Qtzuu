//
//  ContentView.swift
//  bad_query
//
//  Created by Taj C on 7/21/26.
//

// This app is just a basic demo and doesn't show everything bad_query can do, I just threw it together for testing when I first figured out the exploit.

import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @State private var showingImporter = false
    @State private var sandboxHandle: Int64 = -99
    @State private var tempURL: URL?
    @State private var log = "it's sandbox time"
    @State private var path = "/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist"
    
    var body: some View {
        NavigationStack {
            Form {
                Section("Sandbox") {
                    TextField("Path", text: $path)
                    
                    Button("Consume Sandbox Extension") {
                        sandboxHandle = consumeExtension(path)
                    }
                    .disabled(path.isEmpty || sandboxHandle > 0)
                    
                    Button("Release Sandbox Extension") {
                        releaseExtension(handle: sandboxHandle)
                        sandboxHandle = -99
                    }
                    .disabled(sandboxHandle < 0)
                }
                
                Section("File System") {
                    ShareLink(item: URL(fileURLWithPath: path)) {
                        Text("Export At Path")
                    }
                }
                
                Section("Log") {
                    ScrollView {
                        Text(log)
                            .font(.system(.footnote, design: .monospaced))
                            .textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .frame(height: 180)
                    Button("Clear") {
                        log = "it's sandbox time"
                    }
                }
            }
            .navigationTitle("bad_query demo")
            .navigationBarTitleDisplayMode(.inline)
            .fileImporter(isPresented: $showingImporter, allowedContentTypes: [.propertyList]) { result in
                switch result {
                case .success(let url):
                    do {
                        try replace(source: url)
                    } catch {
                        log.append("\nreplace failed: \(error)")
                    }
                case.failure(let error):
                    log.append("\nimport failed: \(error)\n")
                }
            }
        }
    }
    
    func consumeExtension(_ path: String) -> Int64 {
        if sandboxHandle > 0 {
            log.append("\nalready consumed sandbox token!")
            return sandboxHandle
        }
        
        var pathC = path.utf8CString.map { Int8($0) }
        
        log.append("\nattempting consume sandbox extension...")
        let handle = bad_query(&pathC, false, nil, false)
        switch handle {
        case -1:
            log.append("\nfailed to resolve one or more functions")
        case -2:
            log.append("\nfailed to create sandbox query")
        case -3:
            log.append("\noutside of containermanager's sandbox")
        case -4:
            log.append("\nkernel rejected sandbox query")
        default:
            log.append("\nsuccess! handle: \(handle)")
        }
        return handle
    }

    func releaseExtension(handle: Int64) {
        if handle < 0 {
            log.append("\nsandbox extension hasn't been consumed!")
            return
        }
        bad_query_release(handle)
        log.append("\nreleased sandbox extension!")
    }
    
    func replace(source: URL) throws {
        log.append("\nattempting replace mobilegestalt cache...")
        let accessed = source.startAccessingSecurityScopedResource()
        if !accessed {
            log.append("\nfailed to access replacement?")
            throw NSError(domain: "sbhaxx", code: 2)
        }
        guard let replacement = try? Data(contentsOf: source) else {
            log.append("\nfailed to read replacement file data?")
            throw NSError(domain: "sbhaxx", code: 3)
        }
        let path = "/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist"
        let url = URL(fileURLWithPath: path)
        try replacement.write(to: url)
        log.append("\nwrote replacement successfully, reboot to apply!")
    }
    
    func remove() throws {
        log.append("\nattempting remove mobilegestalt cache...")
        do {
            try FileManager.default.removeItem(atPath: "/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist")
        } catch {
            log.append("\nfailed to remove mobilegestalt cache, error: \(error.localizedDescription)")
            throw NSError(domain: "sbhaxx", code: 4)
        }
        log.append("\nremoved mobilegestalt cache, reboot to apply!")
    }
}
