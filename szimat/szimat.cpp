#include <Windows.h>
#include <Shlwapi.h>
#include <cstdio>
#include <ctime>
#include "ConsoleManager.h"
#include "Shared.h"
#include <mutex>
#include "..\minhook\include\MinHook.h"

#define PKT_VERSION 0x0301
#define SNIFFER_ID  15

#define CMSG 0x47534D43 // client to server, CMSG
#define SMSG 0x47534D53 // server to client, SMSG

volatile bool* ConsoleManager::_sniffingLoopCondition = NULL;
std::mutex mtx;
HINSTANCE instanceDLL = NULL;
volatile bool isSigIntOccured = false;
VerInfo verInfo = { NULL, NULL };
char locale[5]  = { "xxXX" };
HookEntry hookEntry;
LPVOID sendDetour, recvDetour;
bool sendHookGood = false, recvHookGood = false;
char dllPath[MAX_PATH] = { NULL };
FILE* fileDump = NULL;

void DumpPacket(DWORD packetType, DWORD connectionId, WORD opcodeSize, CDataStore* dataStore)
{
    mtx.lock();
    // gets the time
    time_t rawTime;
    time(&rawTime);

    DWORD tickCount = GetTickCount();
    DWORD optionalHeaderLength = 0;

    if (!fileDump)
    {
        tm* date = localtime(&rawTime);
        // basic file name format:
        char fileName[MAX_PATH];
        // removes the DLL name from the path
        PathRemoveFileSpec(dllPath);
        // fills the basic file name format
        _snprintf(fileName, MAX_PATH,
            "wowsniff_%s_%u_%u_%d-%02d-%02d_%02d-%02d-%02d.pkt",
            locale, verInfo.expansion, verInfo.build,
            date->tm_year + 1900,
            date->tm_mon + 1,
            date->tm_mday,
            date->tm_hour,
            date->tm_min,
            date->tm_sec);

        // some info
        printf("Sniff dump: %s\n\n", fileName);

        char fullFileName[MAX_PATH];
        _snprintf(fullFileName, MAX_PATH, "%s\\%s", dllPath, fileName);

        WORD pkt_version    = PKT_VERSION;
        BYTE sniffer_id     = SNIFFER_ID;
        BYTE sessionKey[40] = { 0 };

        fileDump = fopen(fullFileName, "wb");
        // PKT 3.1 header
        fwrite("PKT",                           3, 1, fileDump);  // magic
        fwrite((WORD*)&pkt_version,             2, 1, fileDump);  // major.minor version
        fwrite((BYTE*)&sniffer_id,              1, 1, fileDump);  // sniffer id
        fwrite((DWORD*)&verInfo.build,          4, 1, fileDump);  // client build
        fwrite(locale,                          4, 1, fileDump);  // client lang
        fwrite(sessionKey,                     40, 1, fileDump);  // session key
        fwrite((DWORD*)&rawTime,                4, 1, fileDump);  // started time
        fwrite((DWORD*)&tickCount,              4, 1, fileDump);  // started tick's
        fwrite((DWORD*)&optionalHeaderLength,   4, 1, fileDump);  // opional header length

        fflush(fileDump);
    }

    DWORD packetOpcode = opcodeSize == 4
        ? *(DWORD*)dataStore->buffer
        : *(WORD*)dataStore->buffer;

    BYTE* packetData     = dataStore->buffer + opcodeSize;
    DWORD packetDataSize = dataStore->size   - opcodeSize;

    fwrite((DWORD*)&packetType,             4, 1, fileDump);  // direction of the packet
    fwrite((DWORD*)&connectionId,           4, 1, fileDump);  // connection id
    fwrite((DWORD*)&tickCount,              4, 1, fileDump);  // timestamp of the packet
    fwrite((DWORD*)&optionalHeaderLength,   4, 1, fileDump);  // connection id
    fwrite((DWORD*)&dataStore->size,        4, 1, fileDump);  // size of the packet + opcode lenght
    fwrite((DWORD*)&packetOpcode,           4, 1, fileDump);  // opcode

    fwrite(packetData, packetDataSize,         1, fileDump);  // data

#if _DEBUG
    printf("%s Opcode: 0x%04X Size: %-8u\n", packetType == CMSG ? "CMSG" : "SMSG", packetOpcode, packetDataSize);
#endif

    fflush(fileDump);

    mtx.unlock();
}

#define CHECK(p, m) if (!p) { printf(m); p = true; }

typedef DWORD(__thiscall *SendProto)(void*, void*, void*);
DWORD __fastcall SendHook(void* thisPTR, void* dummy , CDataStore* dataStore, DWORD connectionId)
{
    DumpPacket(CMSG, connectionId, 4, dataStore);
    CHECK(sendHookGood, "Send hook is working.\n");
    return reinterpret_cast<SendProto>(sendDetour)(thisPTR, dataStore, (LPVOID)connectionId);
}

#pragma region RecvHook

typedef DWORD(__thiscall *RecvProto)(void*, void*, void*);
DWORD __fastcall RecvHook(void* thisPTR, void* dummy, void* param1, CDataStore* dataStore)
{
    DumpPacket(SMSG, 0, 2, dataStore);
    CHECK(recvHookGood, "Recv hook is working.\n");
    return reinterpret_cast<RecvProto>(recvDetour)(thisPTR, param1, dataStore);
}

typedef DWORD(__thiscall *RecvProto_TBC)(void*, void*, void*, void*);
DWORD __fastcall RecvHook_TBC(void* thisPTR, void* dummy, void* param1, CDataStore* dataStore, void* param3)
{
    DumpPacket(SMSG, (DWORD)param3, 2, dataStore);
    CHECK(recvHookGood, "Recv hook is working.\n");
    return reinterpret_cast<RecvProto_TBC>(recvDetour)(thisPTR, param1, dataStore, param3);
}

typedef DWORD(__thiscall *RecvProto_MOP)(void*, void*, void*, void*);
DWORD __fastcall RecvHook_MOP(void* thisPTR, void* dummy, void* param1, CDataStore* dataStore, void* param3)
{
    DumpPacket(SMSG, (DWORD)param3, 4, dataStore);
    CHECK(recvHookGood, "Recv hook is working.\n");
    return reinterpret_cast<RecvProto_MOP>(recvDetour)(thisPTR, param1, dataStore, param3);
}

typedef DWORD(__thiscall *RecvProto_WOD)(void*, void*, void*, void*, void*);
DWORD __fastcall RecvHook_WOD(void* thisPTR, void* dummy, void* param1, void* param2, CDataStore* dataStore, void* param4)
{
    DumpPacket(SMSG, (DWORD)param4, 4, dataStore);
    CHECK(recvHookGood, "Recv hook is working.\n");
    return reinterpret_cast<RecvProto_WOD>(recvDetour)(thisPTR, param1, param2, dataStore, param4);
}

#pragma endregion

const ProtoEntry ProtoTable[] = {
    /* 0 */{ NULL     , NULL         , "Aplha"     },
    /* 1 */{ &SendHook, &RecvHook    , "Vanilla"   },
    /* 2 */{ &SendHook, &RecvHook_TBC, "TBC"       },
    /* 3 */{ &SendHook, &RecvHook_TBC, "WotLK"     },
    /* 4 */{ &SendHook, &RecvHook_TBC, "Cataclysm" },
    /* 5 */{ &SendHook, &RecvHook_MOP, "MOP"       },
    /* 6 */{ &SendHook, &RecvHook_WOD, "WOD"       },
    /* 7 */{ NULL     , NULL         , "Legion"    },
};

DWORD MainThreadControl(LPVOID /* param */)
{
    // creates the console
    if (!ConsoleManager::Create(&isSigIntOccured))
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);

    // some info
    printf("Welcome to SzimatSzatyor, a WoW injector sniffer.\n");
    printf("SzimatSzatyor is distributed under the GNU GPLv3 license.\n");
    printf("Source code is available at: ");
    printf("http://github.com/Konctantin/SzimatSzatyor\n\n");

    printf("Press CTRL-C (CTRL then c) to stop sniffing ");
    printf("(and exit from the sniffer).\n");
    printf("Note: you can simply re-attach the sniffer without ");
    printf("restarting the WoW.\n\n");

    // gets the build number
    verInfo = GetVerInfoFromProcess();
    // error occured
    if (!verInfo.build)
    {
        printf("Can't determine build number.\n\n");
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }

    if (verInfo.expansion >= sizeof(ProtoTable))
    {
        printf("\nERROR: Unsupported expansion (%u) ", verInfo.expansion);
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }

    printf("Detected build number: %hu expansion: %hu\n", verInfo.build, verInfo.expansion);

    // checks this build is supported or not
    if (!GetOffsets(instanceDLL, verInfo.build, &hookEntry))
    {
        printf("ERROR: This build number is not supported.\n\n");
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }

    // get the base address of the current process
    DWORD baseAddress = (DWORD)GetModuleHandle(NULL);

    DWORD localeAddress = hookEntry.lang;
    // locale stored in reversed string (enGB as BGne...)
    if (localeAddress)
    {
        for (int i = 3; i >= 0; --i)
            locale[i] = *(char*)(baseAddress + localeAddress++);
        printf("Detected client locale: %s\n", locale);
    }

    // gets where is the DLL which injected into the client
    DWORD dllPathSize = GetModuleFileName((HMODULE)instanceDLL, dllPath, MAX_PATH);
    if (!dllPathSize)
    {
        printf("\nERROR: Can't get the injected DLL's location, ");
        printf("ErrorCode: %u\n\n", GetLastError());
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }
    printf("\nDLL path: %s\n", dllPath);

    auto proto = ProtoTable[verInfo.expansion];
    if (!proto.send || !proto.recv)
    {
        printf("\nERROR: Unsupported expansion (%u) ", verInfo.expansion);
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }

    printf("Found '%s' hooks!\n", proto.name);

    MH_CreateHook((LPVOID)(baseAddress + hookEntry.send), proto.send, &sendDetour);
    MH_CreateHook((LPVOID)(baseAddress + hookEntry.recv), proto.recv, &recvDetour);
    printf(">> %s hook is installed.\n", proto.name);

    MH_EnableHook(MH_ALL_HOOKS);

    // loops until SIGINT (CTRL-C) occurs
    while (!isSigIntOccured)
        Sleep(50); // sleeps 50 ms to be nice


    MH_DisableHook(MH_ALL_HOOKS);
    printf("All hook disabled.\n");
    // shutdowns the sniffer
    // note: after that DLL's entry point will be called with
    // reason DLL_PROCESS_DETACH
    FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);

    return 0;
}

BOOL APIENTRY DllMain(HINSTANCE instDLL, DWORD reason, LPVOID /* reserved */)
{
    // called when the DLL is being loaded into the
    // virtual address space of the current process (where to be injected)
    if (reason == DLL_PROCESS_ATTACH)
    {
        instanceDLL = instDLL;
        // disables thread notifications (DLL_THREAD_ATTACH, DLL_THREAD_DETACH)
        DisableThreadLibraryCalls(instDLL);
        MH_Initialize();

        // creates a thread to execute within the
        // virtual address space of the calling process (WoW)
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&MainThreadControl, NULL, 0, NULL);
    }
    // the DLL is being unloaded
    else if (reason == DLL_PROCESS_DETACH)
    {
        // close the dump file
        if (fileDump)
            fclose(fileDump);

        MH_Uninitialize();
        // deallocates the console
        ConsoleManager::Destroy();
    }
    return TRUE;
}