# EpSiLoNPoInTIkEv2.cpp

> ⚠️ Projet en cours de finalisation. NON entièrement fonctionnel dans l'état actuel.

---

## Description

`EpSiLoNPoInTIkEv2.cpp` est un prototype d'exploit C/C++ ciblant Windows, développé autour d'une exploitation
de type **double-free dans `ikeext.dll`** (driver IKEv2 de Windows), référencé
en cours de recherche sous `CVE-2026-33824`.

Le projet regroupe :
- Une couche d'obfuscation complète (machine virtuelle, brouillage de flux de contrôle,
  masquage de chaînes, fausses signatures binaires, inline ASM anti-analyse).
- Un moteur d'exploitation IKEv2 complet (construction de paquets, fragmentation SKF,
  heap grooming multi-thread, ROP chain, primitives arbitraires de lecture/écriture).
- Des mécanismes de contournement de Windows Defender, AMSI et ETW.
- Un listener shell inverse intégré sur le port 4444.
- Une GUI partielle (ListView, ComboBox, status bar) pour inspection de régions mémoire suspectes.

---

## Architecture du code

### 1. Couche obfuscation (`EpSi_OBF_ENDL` / obfusheader inspiré)

Le code utilise une couche d'obfuscation lourde activée à la compilation via `#define EpSi_OBF_ENDL`.
Basé sur [obfusheader.h](https://github.com/ac3ss0r/obfusheader.h), adapté et étendu.

#### Fausses signatures binaires (`FAKE_SIGNS == 1`)
Des sections PE personnalisées sont injectées dans le binaire pour tromper les scanners de
protecteurs connus :
- `.vmp0`, `.vmp1`, `.vmp2` → VMProtect
- `UPX0` → UPX
- `.enigma1`, `.enigma2` → Enigma Protector
- `.winlice` → Themida
- `.petite`, `.aspack`, `.adata`, `.rlp`, `.vlizer`, `.arch`, `.alien`, `.pwdprot`,
  `.dsstext`, `logicoma`, `__wibu00`, `__wibu01`, `PETETRIS`, `.tw`, `.rdata` (Nuitka), `.text` (Screen2Exe), etc.
- Chaînes encodées imitant Enigma (`0x45,0x6e,0x69,...`), Denuvo (`0x64,0x65,0x6E,...`).
- Tableau `FAKE_DONGLE[]` imitant des dongles matériels : `skeydrv.dll`, `HASPDOSDRV`,
  `MARXDEV1.SYS`, `WIBUKEY`, `SNTNLUSB`, `RNBOspro`, etc.

#### Machine virtuelle arithmétique (`VIRT == 1`)
Toutes les opérations arithmétiques et logiques peuvent être routées dans une VM interne
(`Obfh_VirtualMachine`) :
- Les opcodes (`OP__ADD`, `OP__SUB`, ..., `OP__NOP`) sont générés aléatoirement à la
  compilation via `__COUNTER__` et `RND()`.
- Chaque opcode est chiffré : `_VM_ENCRYPT_INT(value) = (value - _VM_MUTATOR_KEY) * ~SALT_CMD`.
- Les opérandes sont salés, inversés (`* -1`), et passés avec des junk values.
- La VM elle-même est truffée de `goto`, de faux `case` négatifs, de `BREAK_STACK_*` (inline ASM
  `xor; jz; .byte 0xE8; cpuid`), de faux JMP (`.byte 0xFF, 0x25`) et de blocs de faux code
  x86_64 pour tromper les décompilateurs.
- Macros exposées : `VM_ADD`, `VM_SUB`, `VM_MUL`, `VM_DIV`, `VM_MOD`, `VM_EQU`, `VM_NEQ`,
  `VM_LSS`, `VM_GTR`, `VM_LEQ`, `VM_GEQ`, `VM_OBF_INT`, `VM_ADD_DBL`, `VM_MUL_DBL`, etc.

#### Contrôle de flux obfusqué (`NO_CFLOW != 1`)
- `#define if(cond)` : chaque `if` injecte un appel `__s_rdtsc()` et un `BAD_CALL` mort.
- `#define else` : injecte un `else if (0) { BAD_CALL; }` mort avant le vrai `else`.
- `#define while(...)` : conditionné par `__s_rdtsc() != 0.1` et un check de pointeur absurde.
- `#define for(...)` : conditionné par `OBFUS_CONDITION_BLOCK`.
- `#define switch(...)` : conditionné par `OBFUS_CONDITION_BLOCK`.
- `#define break` : injecte `if (OBFUS_CONDITION_BLOCK) BREAK_STACK_1` avant chaque `break`.

#### Masquage de chaînes (`HIDE_STRING`)
- `STACK_STRING(str)` : pousse la string sur la stack via compound literal.
- `HIDE_STRING(str)` : combine `obfh_process_hidden_string()` + `__s_rdtsc()` avec `BAD_JMP`
  mort pour masquer la string dans le binaire.

#### Proxies d'API (résolution dynamique complète)
Toutes les fonctions CRT et Win32 sont redirigées :
- **CRT** via `GetProcAddress(LoadLibraryA("msvcrt"), ...)` dynamique : `printf`, `scanf`,
  `sprintf`, `strlen`, `strcmp`, `strcpy`, `strtok`, `memset`, `memcpy`, `strchr`, `strrchr`,
  `rand`, `realloc`, `calloc`, `fopen`, `fclose`, `fread`, `fwrite`, `exit`, `snprintf`,
  `vsprintf`, `vsnprintf`, `getenv`, `system`, `abort`, `atexit`, `getcwd`, `tolower`, `toupper`.
- **Win32** via wrappers `obfh_int_proxy()` sur tous les paramètres : `CreateFile`,
  `ReadFile`, `WriteFile`, `CloseHandle`, `VirtualAlloc`, `VirtualFree`, `CreateThread`,
  `WaitForSingleObject`, `WaitForMultipleObjects`, `ExitProcess`, `GetModuleHandle`,
  `GetModuleFileName`, `HeapCreate`, `HeapAlloc`, `HeapFree`, `GlobalAlloc`, `GlobalFree`,
  `GetTempPath`, `SetEvent`, `ResetEvent`, `Sleep`, `memmove`, `GetParent`, `GetWindowRect`,
  `GetClientRect`, `SetWindowPos`, `SetConsoleTextAttribute`, `GetDesktopWindow`, `GetStockObject`.
- `GetProcAddress` remplacé par `GetProcAddress_custom` : parcours manuel de l'`IMAGE_EXPORT_DIRECTORY`
  (parse PE : `e_lfanew`, `IMAGE_NT_HEADERS`, `IMAGE_DIRECTORY_ENTRY_EXPORT`, `AddressOfFunctions`,
  `AddressOfNames`, `AddressOfNameOrdinals`).
- `LoadLibraryA` obfusqué en chaîne de 6 wrappers imbriqués (`LoadLibraryA_0` à `LoadLibraryA_proxy`),
  avec reconstruction du nom de la DLL caractère par caractère via les variables volatiles
  `_k, _e, _r, _n, _e, _l` et `sprintf`.

#### Anti-debug (`ANTI_DEBUG_V2 == 1`)
- Thread dédié (`ThreadCompareDRs`) : `SuspendThread` sur le thread principal, `GetThreadContext`
  avec `CONTEXT_DEBUG_REGISTERS`, vérification de `Dr0`–`Dr3`, `Dr7`, zeroing via `ad_ZeroDRs`.
- `IsDebuggerPresent_proxy` : charge `kernel32.dll` dynamiquement, reconstruit le nom de la
  fonction `IsDebuggerPresent` caractère par caractère via les variables volatiles (`_I, _s, _D, _e,
  _b, _u, _g, _g, _e, _r, _P, _r, _e, _s, _e, _n, _t`), appel via `GetProcAddress`.
- Macro `ANTI_DEBUG` : double check `IsDebuggerPresent() || IsDebuggerPresent_proxy()`,
  déclenche `loop()` (boucle infinie), `.byte 0xED` (IN privilegié), `BREAK_STACK_1`, `ret` ASM,
  puis `crash()` (`int $3` + `.byte 0xED, 0x00`).

#### Macros BREAK_STACK (anti-analyse de stack)
9 variantes de séquences inline ASM insérées dans les fonctions sensibles :
`xor; jz; .byte 0xE8; cpuid` (variations sur `eax`, `ebx`, `edx`), faux opcodes `0x50`, `0x20`,
`0x00`, `0xEB, 0xE1` (x86), `0xFF, 0x25, 0xF1, 0xF2, 0xF3, 0xF4` (x86_64).

---

### 2. Moteur IKEv2 / Exploit

#### Dépendances
```c
#include "runassys/ntnative.h"
#include "runassys/runassys.h"
#include "runassys/ntdll-stubs/ntdll-stubs.c"
#include "runassys/ntdll-stubs/ntdll.def.c"
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Version.lib")
```

#### Constantes d'exploit
- Cible : `IKEEXT_BASE_ADDRESS = 0x180000000`
- Offset double free : `g_IkeextDoubleFreeOffset = 0x12B960`
- Handler payload IKE : `g_IkeextProcessIkePayload = 0x52220`
- Répertoires PE d'ikeext : Export (`0x1790A0`), Import (`0x179110`), Exception (`0x183000`),
  Reloc (`0x18C000`), LoadConfig (`0x12AE70`), Debug (`0x155CD0`).
- Offsets structures internes : `g_Offset_MMSA_SecurityRealmBlob = 0x208`,
  `g_Offset_PacketContext_Blob = 0xC8`.
- Port IKEv2 : `500 (UDP)`, shell callback : `4444`.

#### Structures IKEv2 définies
`IKE_HEADER`, `IKE_SA_PAYLOAD`, `IKE_PROPOSAL_PAYLOAD`, `IKE_TRANSFORM_PAYLOAD`,
`IKE_NONCE_PAYLOAD` (32 bytes nonce), `IKE_KEY_EXCHANGE_PAYLOAD` (DH 256 bytes),
`IKE_NOTIFY_PAYLOAD`, `IKE_VENDOR_ID_PAYLOAD`, `IKE_SKF_FRAGMENT_PAYLOAD`.

Transforms configurés : AES-CBC-128 (`12`), PRF HMAC-SHA2-256 (`5`),
INTEG HMAC-SHA2-256-128 (`12`), DH MODP-2048 (`14`).

#### Structures DDoS custom
- `IKE_DDOS_AMPLIFIER_PAYLOAD` : facteur d'amplification + 64 octets trigger.
- `IKE_DDOS_LOOP_PAYLOAD` : compteur de boucle + 32 octets loop_code.
- `IKE_DDOS_MEMORY_PAYLOAD` : taille/count allocation + 64 octets heap spray data.

#### Heap grooming
- `HEAP_GROOM_CONTEXT` : handle heap, adresse cible, threads, stop_flag, allocated_chunks.
- `HEAP_GROOM_THREAD_PARAMS` : taille de chunk, itérations, thread_id, SRWLOCK, `use_nt_allocate`.
- `GROOM_CONFIG` : thread_count, itérations, delay, chunk_size, min/max free %.
- Paramètres : 4 threads, chunks de `0x1000`, 1000 itérations, fragmentation entre 30–70%.

#### ROP Chain
Structure `ROP_CHAIN` complète avec tous les gadgets nécessaires :
`pop_rax/rcx/rdx/r8/r9/rsp`, `mov_rax_rsp`, `mov_rcx_rsp`, `mov_rcx_rax`, `mov_rax_rcx`,
`mov_rcx_rdx`, `xor_rax/rcx/rdx`, `jmp_rsp`, `call_rax`, `ret`, `virtual_protect`,
`disable_cfg`, `disable_cet`, `add_rsp`, `sub_rsp`, `stack_pivot`.
Array de 512 gadgets (`rop_chain[MAX_ROP_CHAIN_SIZE]`).

#### Scanner de gadgets ROP
Table `g_rop_patterns[]` de ~50+ patterns byte-signature pour localiser les gadgets dans les modules :
`pop rax; ret`, `pop rcx; ret`, `pop rdx; ret`, ..., `mov [rcx], rax; ret`,
`mov rax, [rcx]; ret`, `jmp rsp`, `VirtualProtect prologue`,
`mov [gs:0x60], rax; ret`, `jmp [rax+0x58]; ret`, `lea rax, [rip+0x0]; jmp rax`,
`add rsp, 0x28; ret`, `cmp rdx/r8/r9, 0x0; je/jne; ret`, etc.

#### Variables globales d'exploit
```c
uint64_t g_KernelBase, g_IkeextBase, g_SystemEprocess;
uint64_t g_IkeextDoubleFreeOffset = 0x12B960;
uint64_t g_IkeextProcessIkePayload = 0x52220;
uint64_t g_PopRax, g_PopRcx, g_PopRdx, g_PopR8, g_PopR9, g_PopRsp;
uint64_t g_MovRaxRsp, g_JmpRsp, g_VirtualProtect, g_DisableCFG, g_StackPivot;
uint64_t g_NtoskrnlBase, g_Kernel32Base, g_NtdllBase, g_HeapBase, g_ShellcodeAddr;
SOCKET g_Socket; struct sockaddr_in g_Target;
EXPLOIT_CONTEXT g_ExploitCtx; ROP_CHAIN g_RopChain;
HEAP_GROOM_CONTEXT g_GroomContext;
MODULE_DATA g_Modules; ROP_GADGET g_Gadgets;
std::vector<SUSPICIOUS_REGION> g_Regions;
```

#### Flux principal (`main`)
1. `InitializeCriticalSection`, `init_debug_info`.
2. `is_hostile_environment()` → exit si sandbox/VM détectée.
3. `disable_amsi()`, `disable_defender()`, `disable_etw()`, `patch_etw()`.
4. `start_shell_listener()` → listener reverse shell port 4444.
5. Parse `argv[1]` (IP cible) + `argv[2]` (port, défaut 500).
6. `init_udp_socket()` + `inet_pton` + `test_target_reachability()`.
7. Construction et envoi des paquets IKEv2 fragmentés (SKF, jusqu'à `SKF_FRAGMENTS + 1` paquets).
8. Déclenchement du double free, heap grooming, placement du shellcode, exécution de la ROP chain.

---

## État actuel

**Le projet est en cours de finalisation et n'est pas entièrement fonctionnel.**

- Certaines fonctions référencées (`disable_amsi`, `disable_defender`, `disable_etw`,
  `patch_etw`, `is_hostile_environment`, `test_target_reachability`, `start_shell_listener`,
  `stop_shell_listener`, `print_usage`, `init_debug_info`) sont déclarées mais peuvent être
  incomplètes ou absentes selon l'état du build.
- Les offsets d'ikeext sont statiques et spécifiques à une build Windows précise.
  Aucun mécanisme de résolution dynamique d'offsets n'est encore finalisé.
- La chaîne ROP est construite mais le placement et l'activation du shellcode ne sont pas
  entièrement intégrés dans l'état actuel.
- Certaines parties de la GUI (ListView, ComboBox, scanning de régions) sont partiellement
  intégrées.
- Le projet peut ne pas compiler sans ajustements du build system, des dépendances
  `runassys/` et des bibliothèques linkées.

---

## Disclaimer

Ce dépôt contient un prototype de recherche en sécurité offensive ciblant un vecteur
d'exploitation réseau de bas niveau (IKEv2/ikeext.dll, Windows).

L'utilisation de ce code est strictement réservée à des environnements de test, de recherche
ou de laboratoire où vous avez une autorisation explicite.

L'auteur décline toute responsabilité pour tout usage illégal, non autorisé ou dommageable
de ce code. Le code est fourni tel quel, sans garantie de fonctionnement, de stabilité ou
d'absence d'effets indésirables.

**Le projet est encore en cours de finalisation et n'est pas entièrement fonctionnel
dans l'état actuel.**
