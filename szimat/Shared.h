/*
* This file is part of SzimatSzatyor.
*
* SzimatSzatyor is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.

* SzimatSzatyor is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.

* You should have received a copy of the GNU General Public License
* along with SzimatSzatyor.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once
#include <wtypes.h>
#include <psapi.h>
#include <Shlwapi.h>
#include <cstdio>
#include <io.h>

#define CMSG 0x47534D43 // client to server, CMSG
#define SMSG 0x47534D53 // server to client, SMSG

const WORD pkt_version    = 0x0301;
const BYTE sniffer_id     = 15;
const BYTE sessionKey[40] = { NULL };

typedef struct {
    void* vTable;
    BYTE* buffer;
    DWORD base;
    DWORD alloc;
    DWORD size;
    DWORD read;
} CDataStore;

typedef struct {
    LPVOID send;
    LPVOID recv;
    char* name;
} ProtoEntry;

typedef struct {
    LPVOID sendDetour;
    LPVOID recvDetour;
    bool sendHookGood = false;
    bool recvHookGood = false;

    char locale[5] = { "xxXX" };
} HookInfo;

// hook entry structure
// stores the offsets which are will be hooked
// every different client version should has different offsets
typedef struct {
    // client build
    WORD build;
    // client expansion
    WORD expansion;
    // offset of NetClient::Send2 to sniff client packets
    DWORD send;
    // offset of NetClient::ProcessMessage to sniff server packets
    DWORD recv;
    // offset of client locale "xxXX"
    DWORD lang;

    bool IsEmpty() { return send == NULL || recv == NULL; }
} WowInfo;

// returns the build number of the client
// returns 0 if an error occurred
// (gets this from file version info of client's exe)
//
// param should be NULL when would like to get the
// path of the _current_ process' executable
// this means the sniffer should call this with NULL because
// the sniffer is just a "thread" which running in WoW
//
// param should NOT be NULL when would like to get the
// path of an _external_ process' executable
// so in the injector the param should contain the handle of a WoW process
bool GetVerInfoFromProcess(HANDLE hProcess, WORD* build, WORD* expansion)
{
    // will contain where the process is which will be injected
    char processExePath[MAX_PATH];

    // size of the path
    DWORD processExePathSize = hProcess
        ? GetModuleFileNameEx(hProcess, NULL, processExePath, MAX_PATH)
        : GetModuleFileName(NULL, processExePath, MAX_PATH);

    if (!processExePathSize)
    {
        printf("ERROR: Can't get path of the process' exe, ErrorCode: %u\n", GetLastError());
        return false;
    }
    printf("ExePath: %s\n", processExePath);

    // size of the file version info
    DWORD fileVersionInfoSize = GetFileVersionInfoSize(processExePath, NULL);
    if (!fileVersionInfoSize)
    {
        printf("ERROR: Can't get size of the file version info,");
        printf("ErrorCode: %u\n", GetLastError());
        return false;
    }

    // allocates memory for file version info
    BYTE* fileVersionInfoBuffer = new BYTE[fileVersionInfoSize];
    // gets the file version info
    if (!GetFileVersionInfo(processExePath, 0, fileVersionInfoSize, fileVersionInfoBuffer))
    {
        printf("ERROR: Can't get file version info, ErrorCode: %u\n", GetLastError());
        delete[] fileVersionInfoBuffer;
        return false;
    }

    // structure of file version info
    // actually this pointer will be pointed to a part of fileVersionInfoBuffer
    VS_FIXEDFILEINFO* fileInfo = NULL;
    // gets the needed info (root) from the file version info resource
    // \ means the root block (VS_FIXEDFILEINFO)
    // note: escaping needed so that's why \\ used
    if (!VerQueryValue(fileVersionInfoBuffer, "\\", (LPVOID*)&fileInfo, NULL))
    {
        printf("ERROR: File version info query is failed.\n");
        delete[] fileVersionInfoBuffer;
        return false;
    }

    *build     = (WORD)( fileInfo->dwFileVersionLS & 0xFFFF);
    *expansion = (WORD)((fileInfo->dwFileVersionMS >> 16) & 0xFFFF);

    delete[] fileVersionInfoBuffer;
    return true;
}

// return the HookEntry from current build
bool GetWowInfo(const HANDLE hProcess, const HINSTANCE moduleHandle, WowInfo* entry)
{
    char fileName[MAX_PATH];
    char dllPath[MAX_PATH];
    char section[6];

    GetModuleFileName((HMODULE)moduleHandle, dllPath, MAX_PATH);
    // removes the DLL name from the path
    PathRemoveFileSpec(dllPath);

    if (!GetVerInfoFromProcess(hProcess, &entry->build, &entry->expansion))
    {
        printf("ERROR: Can't get wow version info!\n\n");
        return false;
    }

#if _WIN64
    _snprintf(fileName, MAX_PATH, "%s\\offsets.x64.ini", dllPath);
#else
    _snprintf(fileName, MAX_PATH, "%s\\offsets.x86.ini", dllPath);
#endif
    _snprintf(section, 6, "%i", entry->build);

    if (_access(fileName, 0) == -1)
    {
        printf("ERROR: File \"%s\" does not exist.\n", fileName);
        printf("\noffsets.ini template:\n");
        printf("[build]\n");
        printf("send=0xDEADBEEF\n");
        printf("recv=0xDEADBEEF\n");
        printf("lang=0xDEADBEEF\n\n");
        return false;
    }

    entry->send = GetPrivateProfileInt(section, "send", 0, fileName);
    entry->recv = GetPrivateProfileInt(section, "recv", 0, fileName);
    entry->lang = GetPrivateProfileInt(section, "lang", 0, fileName);

    return !entry->IsEmpty();
}
