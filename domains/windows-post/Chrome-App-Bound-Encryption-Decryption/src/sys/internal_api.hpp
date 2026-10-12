// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include <Windows.h>
#include "../core/common.hpp"

#ifndef NTSTATUS
using NTSTATUS = LONG;
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif

#ifndef STATUS_BUFFER_OVERFLOW
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

#ifndef STATUS_PENDING
#define STATUS_PENDING ((NTSTATUS)0x00000103L)
#endif

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// NT Structures required for syscalls
struct UNICODE_STRING_SYSCALLS
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
};
using PUNICODE_STRING_SYSCALLS = UNICODE_STRING_SYSCALLS *;

struct OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING_SYSCALLS ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
};
using POBJECT_ATTRIBUTES = OBJECT_ATTRIBUTES *;

struct CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
};
using PCLIENT_ID = CLIENT_ID *;

enum PROCESSINFOCLASS
{
    ProcessBasicInformation = 0,
    ProcessImageFileName = 27
};

struct PROCESS_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
};
using PPROCESS_BASIC_INFORMATION = PROCESS_BASIC_INFORMATION *;

struct PEB_LDR_DATA
{
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
};
using PPEB_LDR_DATA = PEB_LDR_DATA *;

struct RTL_USER_PROCESS_PARAMETERS
{
    BYTE Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING_SYSCALLS ImagePathName;
    UNICODE_STRING_SYSCALLS CommandLine;
};
using PRTL_USER_PROCESS_PARAMETERS = RTL_USER_PROCESS_PARAMETERS *;

struct PEB
{
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE BitField;
    BYTE Reserved3[4];
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
};
using PPEB = PEB *;

enum KEY_VALUE_INFORMATION_CLASS
{
    KeyValueBasicInformation = 0,
    KeyValueFullInformation,
    KeyValuePartialInformation
};

struct KEY_VALUE_PARTIAL_INFORMATION
{
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    UCHAR Data[1];
};
using PKEY_VALUE_PARTIAL_INFORMATION = KEY_VALUE_PARTIAL_INFORMATION *;

enum KEY_INFORMATION_CLASS
{
    KeyBasicInformation = 0
};

enum SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation = 0,
    SystemProcessInformation = 5,
    SystemHandleInformation = 16,
    SystemExtendedHandleInformation = 64
};

enum OBJECT_INFORMATION_CLASS
{
    ObjectBasicInformation = 0,
    ObjectNameInformation = 1,
    ObjectTypeInformation = 2
};

struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
};

struct SYSTEM_HANDLE_INFORMATION_EX
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
};

struct OBJECT_NAME_INFORMATION
{
    UNICODE_STRING_SYSCALLS Name;
    // Variable length name buffer follows
};

struct IO_STATUS_BLOCK
{
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
};
using PIO_STATUS_BLOCK = IO_STATUS_BLOCK*;

enum FILE_INFORMATION_CLASS
{
    FileBasicInformation = 4,
    FileStandardInformation = 5,
    FilePositionInformation = 14,
    FileEndOfFileInformation = 20
};

struct FILE_STANDARD_INFORMATION
{
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
};

struct FILE_POSITION_INFORMATION
{
    LARGE_INTEGER CurrentByteOffset;
};

inline void InitializeObjectAttributes(POBJECT_ATTRIBUTES p, PUNICODE_STRING_SYSCALLS n, ULONG a, HANDLE r, PVOID s)
{
    p->Length = sizeof(OBJECT_ATTRIBUTES);
    p->RootDirectory = r;
    p->Attributes = a;
    p->ObjectName = n;
    p->SecurityDescriptor = s;
    p->SecurityQualityOfService = nullptr;
}

// Syscall Entry Structure - MUST MATCH ASM EXPECTATIONS
struct SYSCALL_ENTRY
{
    PVOID pSyscallGadget;
    UINT nArgs;
    WORD ssn;
};

// Syscall Stubs Structure - MUST MATCH ASM EXPECTATIONS
struct SYSCALL_STUBS
{
    SYSCALL_ENTRY NtAllocateVirtualMemory;
    SYSCALL_ENTRY NtWriteVirtualMemory;
    SYSCALL_ENTRY NtReadVirtualMemory;
    SYSCALL_ENTRY NtCreateThreadEx;
    SYSCALL_ENTRY NtFreeVirtualMemory;
    SYSCALL_ENTRY NtProtectVirtualMemory;
    SYSCALL_ENTRY NtOpenProcess;
    SYSCALL_ENTRY NtGetNextProcess;
    SYSCALL_ENTRY NtTerminateProcess;
    SYSCALL_ENTRY NtQueryInformationProcess;
    SYSCALL_ENTRY NtUnmapViewOfSection;
    SYSCALL_ENTRY NtGetContextThread;
    SYSCALL_ENTRY NtSetContextThread;
    SYSCALL_ENTRY NtResumeThread;
    SYSCALL_ENTRY NtFlushInstructionCache;
    SYSCALL_ENTRY NtClose;
    SYSCALL_ENTRY NtOpenKey;
    SYSCALL_ENTRY NtQueryValueKey;
    SYSCALL_ENTRY NtEnumerateKey;
    SYSCALL_ENTRY NtQuerySystemInformation;
    SYSCALL_ENTRY NtDuplicateObject;
    SYSCALL_ENTRY NtQueryObject;
    SYSCALL_ENTRY NtReadFile;
    SYSCALL_ENTRY NtQueryInformationFile;
    SYSCALL_ENTRY NtSetInformationFile;
};

extern "C"
{
    // Global instance used by ASM
    extern SYSCALL_STUBS g_syscall_stubs;

    // Syscall prototypes
    NTSTATUS NtAllocateVirtualMemory_syscall(HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    NTSTATUS NtWriteVirtualMemory_syscall(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    NTSTATUS NtReadVirtualMemory_syscall(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    NTSTATUS NtCreateThreadEx_syscall(PHANDLE, ACCESS_MASK, LPVOID, HANDLE, LPTHREAD_START_ROUTINE, LPVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T, LPVOID);
    NTSTATUS NtFreeVirtualMemory_syscall(HANDLE, PVOID *, PSIZE_T, ULONG);
    NTSTATUS NtProtectVirtualMemory_syscall(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);
    NTSTATUS NtOpenProcess_syscall(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
    NTSTATUS NtGetNextProcess_syscall(HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);
    NTSTATUS NtTerminateProcess_syscall(HANDLE, NTSTATUS);
    NTSTATUS NtQueryInformationProcess_syscall(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    NTSTATUS NtUnmapViewOfSection_syscall(HANDLE, PVOID);
    NTSTATUS NtGetContextThread_syscall(HANDLE, PCONTEXT);
    NTSTATUS NtSetContextThread_syscall(HANDLE, PCONTEXT);
    NTSTATUS NtResumeThread_syscall(HANDLE, PULONG);
    NTSTATUS NtFlushInstructionCache_syscall(HANDLE, PVOID, ULONG);
    NTSTATUS NtClose_syscall(HANDLE);
    NTSTATUS NtOpenKey_syscall(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
    NTSTATUS NtQueryValueKey_syscall(HANDLE, PUNICODE_STRING_SYSCALLS, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    NTSTATUS NtEnumerateKey_syscall(HANDLE, ULONG, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    NTSTATUS NtQuerySystemInformation_syscall(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    NTSTATUS NtDuplicateObject_syscall(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
    NTSTATUS NtQueryObject_syscall(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    NTSTATUS NtReadFile_syscall(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
    NTSTATUS NtQueryInformationFile_syscall(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
    NTSTATUS NtSetInformationFile_syscall(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
}

namespace Sys {
    // Initialization function
    [[nodiscard]] bool InitApi(bool verbose);
}
