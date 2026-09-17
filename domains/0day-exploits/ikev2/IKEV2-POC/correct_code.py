#!/usr/bin/env python3
"""
Script pour corriger le code IKEV2-POC selon les spécifications :
1. Corriger la structure IKE_TRANSFORM_PAYLOAD selon RFC 4306
2. Définir OBFUSCATION_KEY3 et autres constantes manquantes
3. Ajouter la sélection user/kernel mode
4. Corriger les erreurs de compilation pour Visual Studio
"""

import re

def corriger_fichier(input_file, output_file):
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    # Correction 1: Ajouter la configuration du mode au début
    content = re.sub(
        r'#define _WIN32_WINNT 0x0A00\n#define WINVER 0x0A00\n#define\s+1\s+.*\n\n\n#include <Windows\.h>',
        '''#define _WIN32_WINNT 0x0A00
#define WINVER 0x0A00

// ============================================================================
// CONFIGURATION DU MODE (USER ou KERNEL)
// ============================================================================
// Décommentez la ligne correspondante pour choisir le mode
//#define USER_MODE 1
#define KERNEL_MODE 1

#include <Windows.h>''',
        content,
        count=1
    )
    
    # Correction 2: Ajouter les inclusions nécessaires
    content = re.sub(
        r'#include <iostream>\n\n// ============================================================================',
        '''#include <iostream>

// Inclusions pour le mode User
#include <Winsock2.h>
#include <Ws2tcpip.h>
#include <iphlpapi.h>
#include <bcrypt.h>
#include <wincrypt.h>

// Inclusions pour le mode Kernel
#ifdef KERNEL_MODE
#include <ntddk.h>
#include <ntifs.h>
#include <wdm.h>
#endif

// Déclarations des types et fonctions NT pour éviter les erreurs de compilation
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef LONG NTSTATUS;
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS 0x00000000
#endif

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessBreakOnTermination = 29
} PROCESSINFOCLASS;

// Déclaration de PROCESS_DEBUG_PORT
typedef struct _PROCESS_DEBUG_PORT {
    HANDLE DebugPort;
} PROCESS_DEBUG_PORT;

// ============================================================================''',
        content,
        count=1
    )
    
    # Correction 3: Définir OBFUSCATION_KEY3 et OBFUSCATION_KEY4
    content = re.sub(
        r'#define OBFUSCATION_KEY1 \(uint8_t\)\(GetTickCount\(\) & 0xFF\)\n#define OBFUSCATION_KEY2 \(uint8_t\)\(\(GetTickCount\(\) >> 8\) & 0xFF\)\n#define RANDOMIZATION_SEED',
        '''// Clés d'obfuscation - CORRIGÉ: Ajout de OBFUSCATION_KEY3 et OBFUSCATION_KEY4
#define OBFUSCATION_KEY1 (uint8_t)(GetTickCount() & 0xFF)
#define OBFUSCATION_KEY2 (uint8_t)((GetTickCount() >> 8) & 0xFF)
#define OBFUSCATION_KEY3 (uint8_t)((GetTickCount() >> 16) & 0xFF)
#define OBFUSCATION_KEY4 (uint8_t)((GetTickCount() >> 24) & 0xFF)
#define RANDOMIZATION_SEED''',
        content,
        count=1
    )
    
    # Correction 4: Ajouter les constantes manquantes DDOS_EXTRA_SIZE et SKF_DDOS_EXTRA_SIZE
    content = re.sub(
        r'#define MAX_CHUNK_SIZE 0x10000\n#define MALFORMED_DATA_SIZE 2048\n#define SKF_FRAGMENTS 4',
        '''#define MAX_CHUNK_SIZE 0x10000
#define MALFORMED_DATA_SIZE 2048
#define DDOS_EXTRA_SIZE 512  // CORRIGÉ: Ajout de la constante manquante
#define SKF_DDOS_EXTRA_SIZE 256  // CORRIGÉ: Ajout de la constante manquante
#define SKF_FRAGMENTS 4''',
        content,
        count=1
    )
    
    # Correction 5: Corriger la structure IKE_TRANSFORM_PAYLOAD selon RFC 4306
    content = re.sub(
        r'typedef struct _IKE_TRANSFORM_PAYLOAD \{\s*uint8_t next_payload;\s*uint8_t critical;\s*uint16_t length;\s*uint8_t transform_type;\s*uint8_t reserved1;\s*uint8_t reserved2;\s*uint16_t transform_id;\s*uint8_t reserved3;\s*uint8_t attributes_len;\s*\} IKE_TRANSFORM_PAYLOAD;',
        '''// Structure corrigée selon RFC 4306 Section 3.3.2
typedef struct _IKE_TRANSFORM_PAYLOAD {
    uint8_t next_payload;    // Next Payload (1 octet)
    uint8_t reserved1;       // Réservé (1 octet) - RFC 4306
    uint16_t length;         // Longueur totale (2 octets)
    uint8_t transform_type;   // Type de transform (1 octet)
    uint8_t reserved2;       // Réservé (1 octet) - RFC 4306
    uint16_t transform_id;    // Identifiant du transform (2 octets)
} IKE_TRANSFORM_PAYLOAD;''',
        content,
        count=1
    )
    
    # Correction 6: Supprimer la ligne problématique "#define  1"
    content = re.sub(r'#define\s+1\s+.*\n', '', content)
    
    # Correction 7: Supprimer les lignes vides en trop au début
    content = re.sub(r'\n\n\n+', '\n\n', content)
    
    # Correction 8: Ajouter les pragma comment pour les bibliothèques à la fin
    if '#pragma comment(lib,' not in content:
        content = content.rstrip() + '''

// ============================================================================
// LINKER DIRECTIVES - Bibliothèques nécessaires pour Visual Studio
// ============================================================================
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "Vssapi.lib")
'''
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"Fichier corrigé sauvegardé dans {output_file}")

if __name__ == '__main__':
    corriger_fichier('IkEv2.cpp', 'IkEv2_corrige.cpp')
