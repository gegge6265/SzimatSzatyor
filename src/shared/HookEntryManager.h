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
#include <map>

#define PKT_VERSION     0x0301
#define SNIFFER_ID      15
// todo: use it
#define CLIENT_BUILD    17688
#define SEND2           0x3988D7
#define PROCESS_MESSAGE 0x3965BB
#define CLEINET_LOCALE  0xE7080C

#define FILL_OFFSET(build, send2, processMessage, locale) _hookEntryMap[(build)] = HookEntry((send2), (processMessage), (locale))

// list of supported client build numbers
#define WOW_CLASS_5875  5875
#define WOW_TBC_8606    8606
#define WOW_WLK_12340   12340
#define WOW_CATA_13623  13623
#define WOW_CATA_15595  15595
#define WOW_MOP_16135   16135
#define WOW_MOP_16357   16357
#define WOW_MOP_16650   16650
#define WOW_MOP_16709   16709
#define WOW_MOP_16826   16826
#define WOW_MOP_16981   16981
#define WOW_MOP_16983   16983
#define WOW_MOP_16992   16992
#define WOW_MOP_17055   17055
#define WOW_MOP_17056   17056
#define WOW_MOP_17093   17093
#define WOW_MOP_17116   17116
#define WOW_MOP_17124   17124
#define WOW_MOP_17128   17128
#define WOW_MOP_17359   17359
#define WOW_MOP_17371   17371
#define WOW_MOP_17399   17399
#define WOW_MOP_17538   17538
#define WOW_MOP_17658   17658
#define WOW_MOP_17688   17688

// stores and manages hook entries
// this will be compiled into a static lib
// so both of the injector and the DLL too can use this class
class HookEntryManager
{
public:
    // hook entry structure
    // stores the offsets which are will be hooked
    // every different client version should has different offsets
    struct HookEntry
    {
        // default constructor is needed for std::map
        HookEntry()
        {
            send2_AddressOffset = 0;
            processMessage_AddressOffset = 0;
            locale_AddressOffset = 0;
        }
        // constructor
        HookEntry(DWORD send2, DWORD processMessage, DWORD locale)
        {
            send2_AddressOffset = send2;
            processMessage_AddressOffset = processMessage;
            locale_AddressOffset = locale;
        }

        // offset of NetClient::Send2 to sniff client packets
        DWORD send2_AddressOffset;
        // offset of NetClient::ProcessMessage to sniff server packets
        DWORD processMessage_AddressOffset;
        // offset of client locale "xxXX"
        DWORD locale_AddressOffset;
    };

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
    static WORD GetBuildNumberFromProcess(HANDLE hProcess = NULL);

    // just fills manually all the avaiable hook entries
    // this is some kind of initialization of the class
    static void FillHookEntries()
    {
        //             build          send2     pm     locale
        FILL_OFFSET(WOW_CLASS_5875, 0x1B5630, 0x137AA0, 0);

        FILL_OFFSET(WOW_TBC_8606,   0x0203B0, 0x15F440, 0);

        FILL_OFFSET(WOW_WLK_12340,  0x0675F0, 0x231FE0, 0);

        FILL_OFFSET(WOW_CATA_13623, 0x15EF20, 0x090360, 0);
        FILL_OFFSET(WOW_CATA_15595, 0x089590, 0x0873D0, 0);

        FILL_OFFSET(WOW_MOP_16135,  0x3F9AE0, 0x3F7710, 0);
        FILL_OFFSET(WOW_MOP_16357,  0x40C5D0, 0x40A210, 0);
        FILL_OFFSET(WOW_MOP_16650,  0x448D10, 0x446720, 0);
        FILL_OFFSET(WOW_MOP_16709,  0x448FB0, 0x446A00, 0);
        FILL_OFFSET(WOW_MOP_16826,  0x448E40, 0x446880, 0);
        FILL_OFFSET(WOW_MOP_16981,  0x363B57, 0x361C6D, 0);
        FILL_OFFSET(WOW_MOP_16983,  0x36400D, 0x362123, 0);
        FILL_OFFSET(WOW_MOP_16992,  0x36424A, 0x362360, 0);
        FILL_OFFSET(WOW_MOP_17055,  0x363F76, 0x36206E, 0);
        FILL_OFFSET(WOW_MOP_17056,  0x3E43D9, 0x3E1ECC, 0);
        FILL_OFFSET(WOW_MOP_17093,  0x3EED60, 0x3EC853, 0);
        FILL_OFFSET(WOW_MOP_17116,  0x364654, 0x36276A, 0);
        FILL_OFFSET(WOW_MOP_17124,  0x3F3B0F, 0x3F1490, 0);
        FILL_OFFSET(WOW_MOP_17128,  0x363C88, 0x361D9B, 0);
        FILL_OFFSET(WOW_MOP_17359,  0x391942, 0x38F9C5, 0);
        FILL_OFFSET(WOW_MOP_17371,  0x39192A, 0x38F9AD, 0);
        FILL_OFFSET(WOW_MOP_17399,  0x39199E, 0x38FA21, 0);
        FILL_OFFSET(WOW_MOP_17538,  0x38F1A9, 0x38D225, 0);
        FILL_OFFSET(WOW_MOP_17658,  0x3988D7, 0x3965BB, 0xE7080C);
        FILL_OFFSET(WOW_MOP_17688,  0x3988D7, 0x3965BB, 0xE7080C);
    }

    // returns true if hook entry exists for this specified build number
    // otherwise false
    static bool IsHookEntryExists(WORD buildNumber)
    {
        return _hookEntryMap.find(buildNumber) != _hookEntryMap.end();
    }

    static HookEntry const& GetHookEntry(WORD buildNumber)
    {
        return _hookEntryMap[buildNumber];
    }

    // type for storing hook entries
    typedef std::map<WORD /* buildNumber */, HookEntry> HookEntryMap;
    // stores hook entries
    // key for the hook entry is the build number of the client
    static HookEntryMap _hookEntryMap;
};
