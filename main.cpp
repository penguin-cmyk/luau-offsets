#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <cstdint>


struct Pattern final {
    std::string pattern;
    std::string name;
    std::string library;
};

bool ConvertPatternToBytes(const std::string& input_pattern, std::vector<uint8_t>& out_bytes, std::string& out_mask)
{
    out_bytes.clear();
    out_mask.clear();
    out_bytes.reserve(input_pattern.size() / 2);
    out_mask.reserve(input_pattern.size() / 2);

    for (size_t pos = 0; pos < input_pattern.length();) {
        while (pos < input_pattern.length() && std::isspace(input_pattern[pos])) {
            ++pos;
        }

        if (pos >= input_pattern.length()) {
            break;
        }

        if (input_pattern[pos] == '?') {
            out_bytes.push_back(0);
            out_mask += '?';
            ++pos;
            if (pos < input_pattern.length() && input_pattern[pos] == '?') {
                ++pos;
            }
            continue;
        }

        if (pos + 1 >= input_pattern.length()) {
            return false;
        }

        auto char_to_nibble = [](char c) -> int {
            if (std::isdigit(c)) return c - '0';
            if (std::tolower(c) >= 'a' && std::tolower(c) <= 'f') {
                return std::tolower(c) - 'a' + 10;
            }
            return -1;
        };

        int upper_nibble = char_to_nibble(input_pattern[pos]);
        int lower_nibble = char_to_nibble(input_pattern[pos + 1]);

        if (upper_nibble < 0 || lower_nibble < 0) {
            return false;
        }

        out_bytes.push_back(static_cast<uint8_t>((upper_nibble << 4) | lower_nibble));
        out_mask += 'x';
        pos += 2;
    }

    return !out_bytes.empty();
}

bool MatchPattern(const uint8_t* data, const uint8_t* pattern, const std::string& mask, size_t pattern_length)
{
    for (size_t i = 0; i < pattern_length; ++i) {
        if (mask[i] == 'x' && data[i] != pattern[i]) {
            return false;
        }
    }
    return true;
}

uintptr_t SearchMemoryRegion(
        HANDLE process_handle,
        uintptr_t start_address,
        size_t region_size,
        const std::vector<uint8_t>& pattern,
        const std::string& mask
)
{
    if (pattern.empty() || mask.empty() || pattern.size() != mask.size()) {
        return 0;
    }

    std::vector<uint8_t> memory_buffer(region_size);
    SIZE_T bytes_read = 0;

    if (!ReadProcessMemory(process_handle, reinterpret_cast<LPCVOID>(start_address),
                           memory_buffer.data(), region_size, &bytes_read)) {
        return 0;
    }

    if (bytes_read < pattern.size()) {
        return 0;
    }

    for (size_t offset = 0; offset <= bytes_read - pattern.size(); ++offset) {
        if (MatchPattern(memory_buffer.data() + offset, pattern.data(), mask, pattern.size())) {
            return start_address + offset;
        }
    }

    return 0;
}

DWORD RbxPid(const char* processName)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(snapshot, &entry)) {
        CloseHandle(snapshot);
        return 0;
    }

    do {
        if (strcmp(entry.szExeFile, processName) == 0) {
            DWORD pid = entry.th32ProcessID;
            CloseHandle(snapshot);
            return pid;
        }
    } while (Process32Next(snapshot, &entry));

    CloseHandle(snapshot);
    return 0;
}

uintptr_t Base(DWORD pid)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    MODULEENTRY32 entry;
    entry.dwSize = sizeof(MODULEENTRY32);

    if (Module32First(snapshot, &entry) == 0) {
        CloseHandle(snapshot);
        return 0;
    }

    CloseHandle(snapshot);
    return (uintptr_t)(entry.modBaseAddr);
}

uintptr_t BaseSize(DWORD pid)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    MODULEENTRY32 entry;
    entry.dwSize = sizeof(MODULEENTRY32);

    if (Module32First(snapshot, &entry) == 0) {
        CloseHandle(snapshot);
        return 0;
    }

    CloseHandle(snapshot);
    return (uintptr_t)(entry.modBaseSize);
}



int main()
{
    DWORD pid = RbxPid("RobloxPlayerBeta.exe");
    if (!pid) {
        std::cout << "Roblox not found" << std::endl;
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid);
    uintptr_t moduleBase = Base(pid);
    SIZE_T moduleSize = BaseSize(pid);

    std::vector<Pattern> patterns = {
            // lmem
            {"48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B F1 49 63 E8", "newpage", "lmem"},
            {"48 89 5C 24 ? 57 48 83 EC ? 48 8B FA 41 0F B6 D9", "newclasspage", "lmem"},
            {"48 83 EC ? 4D 8B D1 4C 8B D9 4D 8B 49", "freeclasspage", "lmem"},
            {"40 53 48 83 EC ? 4C 63 CA 48 8B 51 ? 4E 8B 44 CA", "newblock", "lmem"},
            {"40 53 48 83 EC ? 4C 63 CA 48 8B 51 ? ? ? ? ? 4C 8B 83", "newgcoblock", "lmem"},
            {"48 83 EC ? 4C 8B 51 ? 49 83 E8", "freeblock", "lmem"},
            {"48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B 79 ? 49 8D 40", "luaM_free", "lmem"},
            {"48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B 59 ? 49 8B F8 41 0F B6 F1", "luaM_freegco", "lmem"},
            {"40 56 41 54 41 55 48 83 EC ? 48 8B 41", "luaM_visitgco", "lmem"},
            {"48 83 EC ? 48 8D 05 ? ? ? ? 48 89 44 24 ? 48 8B 54 24 ? 48 81 EA ? ? ? ? E8 ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? 48 89 5C 24", "luaM_toobig", "lmem"},

            // lstate
            {"48 89 5C 24 ? 57 48 83 EC ? 48 8B 41 ? 48 8B D9 48 8B 79 ? 4C 8B 51", "close_state", "lstate"},
            {"48 89 5C 24 ? 55 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 41 B9", "lua_newstate", "lstate"},
            {"40 53 55 56 57 48 83 EC ? 0F BE 15", "f_luaopen", "lstate"},

            // lbaselib
            {"48 89 5C 24 ? 48 89 74 24 ? 57 41 54 41 55 41 56 41 57 48 83 EC ? 4C 8B 51", "auxopen", "lbaselib"},
            {"48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 54 41 55 41 56 41 57 48 83 EC ? 0F B6 41 ? 48 8B D9", "luaopen_base", "lbaselib"},
            {"40 53 48 83 EC ? 48 8B D9 4C 8D 05 ? ? ? ? 48 8B 49", "newproxy", "lbaselib"},
            {"48 83 EC ? 48 8B 41 ? 48 3B 41 ? 73", "tostring", "lbaselib"},
            {"40 53 48 83 EC ? 48 8B D9 85 D2 75", "luaB_xpcallcont", "lbaselib"},

            // ltm
            {"48 83 EC ? 4C 63 42 ? 4C 8B D1", "luaT_objtypenamestr", "ltm"},
            {"48 83 EC ? E8 ? ? ? ? 48 83 C0 ? 48 83 C4 ? C3 ? ? ? ? ? ? ? ? ? ? ? ? ? ? 48 89 5C 24 ? 48 89 6C 24", "luaT_objtypename", "ltm"},

            // lapi
            {"89 54 24 ? 53 55 56 57 41 54 41 55 41 56 41 57 48 83 EC ? 4C 8B 41", "lua_rawcheckstack", "lapi"},
            {"48 83 EC ? 4C 8D 15 ? ? ? ? 85 D2", "luaA_toobject", "lapi"},
            {"48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 4C 8B 49 ? 49 8B F8", "lua_pushvfstring", "lapi"},
            {"41 B9 ? ? ? ? 4C 8B C1 41 3B D1", "pseudo2addr", "lapi"},
            {"48 83 EC ? 4C 8B D1 48 3B CA", "lua_xmove", "lapi"},
            {"48 89 54 24 ? 4C 89 44 24 ? 4C 89 4C 24 ? 53 48 83 EC ? 48 8B 51", "lua_pushfstringL", "lapi"},

            // laux
            {"48 8B C4 48 89 50 ? 4C 89 40 ? 4C 89 48 ? 53 55 56", "luaL_errorL", "laux"},
            {"48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 49 8B F8 8B F2 48 8B D9 E8 ? ? ? ? 44 8B C6", "luaL_argerrorL", "laux"},
            {"48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 49 8B E8 8B F2", "luaL_typeerrorL", "laux"},
            {"44 89 4C 24 ? 4C 89 44 24 ? 53 55 56 57 41 54 41 55 41 56 41 57 48 81 EC", "luaL_findtable", "laux"},
            {"48 89 4C 24 ? 53 55 56 57 41 54 41 55 41 56 41 57 48 81 EC ? ? ? ? 45 33 FF", "luaL_where", "laux"},
            {"40 53 41 56 41 57 48 83 EC ? 0F B6 41", "luaL_getmetafield", "laux"},
            {"48 89 5C 24 ? 4C 89 44 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 83 EC ? 4D 8B E8 4C 8B E2", "luaL_register", "laux"},
            {"40 53 55 56 57 41 54 41 55 41 56 48 83 EC ? 0F B6 41", "luaL_newmetatable", "laux"},
            {"48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 63 FA 49 8B F0", "luaL_checklstring", "laux"},
            {"40 53 57 48 83 EC ? 4C 8B 41", "luaL_checkany", "laux"},
            {"48 83 EC ? 44 8B CA 4C 8B D1", "luaL_checktype", "laux"},
            {"48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 83 EC ? 48 8B 71 ? 48 8B D9", "luaL_pushresult", "laux"},
            {"48 89 5C 24 ? 57 48 83 EC ? 48 8B 41 ? 48 8B F9 48 3B 41", "currfuncname", "laux"},

            // ldebug
            {"48 8B C4 48 89 50 ? 4C 89 40 ? 4C 89 48 ? 53 48 81 EC ? ? ? ? 48 8B D9", "luaG_runerrorL", "ldebug"},
            {"48 89 54 24 ? 48 89 4C 24 ? 53 55 56 57 41 57", "auxgetinfo", "ldebug"},

            // lobject
            {"40 53 55 56 57 41 54 41 55 41 56 48 81 EC ? ? ? ? 49 8B D8", "luaO_pushvfstring", "lobject"},
            {"48 89 5C 24 ? 57 48 83 EC ? ? ? ? ? 49 8B D8 48 8B F9 3C", "luaO_chunkid", "lobject"},
            {"48 89 54 24 ? 4C 89 44 24 ? 4C 89 4C 24 ? 48 83 EC ? 4C 8D 44 24 ? E8 ? ? ? ? 48 83 C4 ? C3 ? ? ? ? ? ? ? ? ? ? ? ? ? ? 48 89 5C 24", "luaO_pushfstring", "lobject"},
            // lfunc
            {"48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? ? ? ? ? 49 8B F0 4C 63 82", "luaF_freeproto", "lfunc"},
            {"48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 0F BE 15", "luaF_newproto", "lfunc"},

            // ldo
            {"48 83 EC ? 44 8B C2 48 8B D1 48 8D 4C 24", "luaD_throw", "ldo"},
            {"48 89 4C 24 ? 48 83 EC ? 48 8B C2", "luaD_rawrunprotected", "ldo"},

            // lvmexecute
            {"80 79 06 00 0F 85 ? ? ? ? E9 ? ? ? ?", "luau_execute", "lvmexecute"},

            // lvmutils
            {"48 89 5C 24 ? 48 89 6C 24 ? 56 41 54 41 55 41 56 41 57 48 83 EC ? 45 33 E4", "luaV_gettable", "lvmutils"},
            {"48 8B C4 4C 89 48 ? 4C 89 40 ? 48 89 48 ? 55 53 57", "luaV_settable", "lvmutils"},
            {"48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 41 54 41 56 41 57 48 83 EC ? 8B 44 24", "luaV_getimport", "lvmutils"},
            // lgc
            {"48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC ? 48 8B 59 ? B8", "luaC_step", "lgc"},


            // misc
            {"48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 49 8B F8 48 8B F2 48 8B D9 8B 81", "GetLuaState", "misc"},
            {"48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B EA 48 8B F9 48 85 D2 0F 84 ? ? ? ? 48 8B 5A ? E8 ? ? ? ? 44 0F B7 8B ? ? ? ? 44 0F B7 80", "ReuqestCode", "misc"},
            {"48 89 54 24 ? 4C 89 44 24 ? 4C 89 4C 24 ? 55 53 56 57 41 54 41 55", "RbxPrint", "misc"},
            {"? ? ? 83 F8 ? 77 ? 48 8D 15 ? ? ? ? 8B 8C 82 ? ? ? ? 48 03 CA FF E1 48 B8", "get_capabilites", "misc"},
            {"48 89 4C 24 ? 48 89 54 24 ? 4C 89 44 24 ? 4C 89 4C 24 ? 48 83 EC ? 48 8D 4C 24", "std_runtime_error", "misc"},

            // Rbx::LuaBridge
            {"48 89 5C 24 ? 4C 89 4C 24 ? 48 89 54 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 83 EC ? 49 63 F8", "Bridge_registerClass", "LuaBridge"},
            {"40 53 56 57 41 56 41 57 48 83 EC ? 4C 8D 05", "PhysicalPropertiesBridge_registerClass", "LuaBridge"},
            {"40 53 56 57 41 54 41 56", "Vector3Bridge_registerClass", "LuaBridge"},
            {"48 89 5C 24 ? 4C 89 44 24 ? 48 89 54 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 83 EC ? 4C 8D 05 ? ? ? ? 4C 8B E9 48 8D 15 ? ? ? ? E8 ? ? ? ? 48 83 3D ? ? ? ? ? 0F 84 ? ? ? ? 48 8D 35 ? ? ? ? 48 C7 84 24 ? ? ? ? ? ? ? ? 48 8B FE 33 DB 48 BD ? ? ? ? ? ? ? ? 0F 1F 40 ? 0F 1F 84 00 ? ? ? ? 44 8B 05 ? ? ? ? BA ? ? ? ? 49 8B CD E8 ? ? ? ? F2 0F 10 44 33", "Vector2Bridge_registerClass", "LuaBridge"},

            // Rbx::ScriptContext
            {"48 8B C4 44 89 48 ? 4C 89 40 ? 48 89 50 ? 48 89 48 ? 53", "resume", "ScriptContext"},
            {"40 53 55 56 57 41 56 48 83 EC ? 48 8B D9 48 8B 49", "sandboxThread", "ScriptContext"},
            {"48 89 5C 24 ? 48 89 54 24 ? 48 89 4C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? B8 ? ? ? ? E8 ? ? ? ? 48 2B E0 41 8B D9", "openState", "ScriptContext"},
            {"48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 54 41 55 41 56 41 57 48 83 EC ? 48 8B 51", "Lua_protect_metatable", "ScriptContext"},
            {"40 53 48 83 EC ? 48 8B C2 48 8B D9 FF 15", "loadLibraryProtected", "ScriptContext"},

            // Task
            {"48 89 5C 24 ? 55 56 57 48 81 EC ? ? ? ? 48 8B D9 33 ED", "spawn", "task"},
            {"48 89 5C 24 ? 48 89 6C 24 ? 56 57 41 56 48 81 EC ? ? ? ? 48 8B F9 45 33 F6 44 38 35", "defer", "task"},
            {"48 89 5C 24 ? 48 89 74 24 ? 57 48 81 EC ? ? ? ? 48 8B D9 33 FF 48 85 C9 ? ? 48 8B 41 ? EB ? 48 8B C7 48 8B 48 ? 48 85 C9 74 ? 39 79 ? 0F 85 ? ? ? ? 40 38 3D ? ? ? ? 74 ? 45 33 C9 4C 8D 84 24 ? ? ? ? 33 D2 48 8D 35 ? ? ? ? 48 8B CE FF 15 ? ? ? ? 85 C0 0F 84 ? ? ? ? 39 BC 24 ? ? ? ? 74 ? 48 89 74 24 ? C7 44 24 ? ? ? ? ? E8 ? ? ? ? 89 7C 24 ? 45 33 C0 33 D2 48 8B CE FF 15 ? ? ? ? 85 C0 0F 84 ? ? ? ? 80 3D ? ? ? ? ? 0F 84 ? ? ? ? 48 8D 05 ? ? ? ? 48 89 44 24 ? 48 89 7C 24 ? 48 89 7C 24 ? 48 89 7C 24 ? 48 C7 44 24 ? ? ? ? ? B9 ? ? ? ? E8 ? ? ? ? 48 8B C8 48 C7 44 24 ? ? ? ? ? 48 C7 44 24 ? ? ? ? ? 0F 28 05 ? ? ? ? ? ? ? 0F 28 0D ? ? ? ? 0F 11 48 ? 0F 28 05 ? ? ? ? 0F 11 40 ? 0F 28 0D ? ? ? ? 0F 11 48 ? 0F 28 05 ? ? ? ? 0F 11 40 ? 8B 05", "synchronize", "task"},
            {"48 89 5C 24 ? 48 89 74 24 ? 57 48 81 EC ? ? ? ? 48 8B D9 33 FF 48 85 C9 ? ? 48 8B 41 ? EB ? 48 8B C7 48 8B 48 ? 48 85 C9 74 ? 39 79 ? 0F 85 ? ? ? ? 40 38 3D ? ? ? ? 74 ? 45 33 C9 4C 8D 84 24 ? ? ? ? 33 D2 48 8D 35 ? ? ? ? 48 8B CE FF 15 ? ? ? ? 85 C0 0F 84 ? ? ? ? 39 BC 24 ? ? ? ? 74 ? 48 89 74 24 ? C7 44 24 ? ? ? ? ? E8 ? ? ? ? 89 7C 24 ? 45 33 C0 33 D2 48 8B CE FF 15 ? ? ? ? 85 C0 0F 84 ? ? ? ? 80 3D ? ? ? ? ? 0F 84 ? ? ? ? 48 8D 05 ? ? ? ? 48 89 44 24 ? 48 89 7C 24 ? 48 89 7C 24 ? 48 89 7C 24 ? 48 C7 44 24 ? ? ? ? ? B9 ? ? ? ? E8 ? ? ? ? 48 8B C8 48 C7 44 24 ? ? ? ? ? 48 C7 44 24 ? ? ? ? ? 0F 28 05 ? ? ? ? ? ? ? 0F 28 0D ? ? ? ? 0F 11 48 ? 0F 28 05 ? ? ? ? 0F 11 40 ? 0F 28 0D ? ? ? ? 0F 11 48 ? 0F 28 05 ? ? ? ? 0F 11 40 ? F2 0F 10 0D", "desynchronize", "task"},
            {"48 8B C4 48 89 58 ? 55 56 57 41 56 41 57 48 8D 68 ? 48 81 EC ? ? ? ? 0F 29 70 ? 0F 29 78 ? 48 8B F9", "delay", "task"},
            {"40 53 56 57 48 81 EC ? ? ? ? 48 8B D9 80 3D", "wait", "task"},
            {"48 83 EC ? 48 8B 41 ? 4C 8B C9 48 8D 0D", "cancel", "task"},

            // coroutine
            {"40 53 41 56 48 83 EC ? 48 8B 41", "create", "coroutine"},
            {"0F B6 41 ? A8 ? 74 ? 48 8B 51", "running", "coroutine"},
            {"40 57 48 83 EC ? 48 8B 51 ? 48 8B F9 48 8D 0D", "status", "coroutine"},
            {"48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 41 56 48 83 EC ? 48 8B D9 E8", "wrap", "coroutine"},
            {"48 83 EC ? 4C 8B 41 ? 0F B7 41", "yield", "coroutine"},
            {"0F B7 41 ? 33 D2 66 39 41", "isyieldable", "coroutine"},
            {"40 53 41 57 48 83 EC ? 48 8B D9 48 8D 15", "close", "coroutine"},

            // debug
            {"40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 41 ? 48 8D 15", "info", "ldblib"},
            {"40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B F9 4C 8D 2D", "traceback", "ldblib"},

            // lvmload
            {"48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 45 33 DB 4C 8B D1", "remapUserdataTypes", "lvmload"},
            {"33 C0 4C 8B D9 8B C8 66 0F 1F 84 00", "readVarInt", "lvmload"},
            {"48 89 54 24 ? 48 89 4C 24 ? 55 53 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 7A", "loadsafe", "lvmload"},
            {"4C 89 44 24 ? 48 89 4C 24 ? 53 56 57 41 54 41 55 41 56 41 57 48 81 EC ? ? ? ? 45 8B E9", "luau_load", "lvmload"}
    };

    uintptr_t startAddress = moduleBase;
    uintptr_t endAddress = moduleBase + moduleSize;

    MEMORY_BASIC_INFORMATION memInfo;
    std::map<std::string, std::vector<std::pair<std::string, uintptr_t>>> results;

    for (const auto& pat : patterns) {
        std::vector<BYTE> byte_sequence;
        std::string pattern_mask;

        if (!ConvertPatternToBytes(pat.pattern, byte_sequence, pattern_mask)) {
            std::cerr << "Invalid pattern format for: " << pat.name << '\n';
            results[pat.library].emplace_back(pat.name, 0);
            continue;
        }

        bool is_match_found = false;
        uintptr_t scan_addr = startAddress;
        MEMORY_BASIC_INFORMATION region_info{};

        do {
            if (VirtualQueryEx(hProcess, (LPCVOID)scan_addr, &region_info, sizeof(region_info)) != sizeof(region_info)) {
                break;
            }

            if (region_info.State == MEM_COMMIT &&
                !(region_info.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
                (uintptr_t)region_info.BaseAddress >= startAddress &&
                (uintptr_t)region_info.BaseAddress < endAddress) {

                uintptr_t base = (uintptr_t)region_info.BaseAddress;
                SIZE_T size = region_info.RegionSize;

                if (base + size > endAddress) {
                    size = endAddress - base;
                }

                if (uintptr_t match = SearchMemoryRegion(hProcess, base, size, byte_sequence, pattern_mask)) {
                    results[pat.library].emplace_back(pat.name, match - moduleBase);
                    is_match_found = true;
                    break;
                }
            }

            scan_addr = (uintptr_t)region_info.BaseAddress + region_info.RegionSize;
        } while (scan_addr < endAddress);

        if (!is_match_found) {
            results[pat.library].emplace_back(pat.name, 0);
        }
    }

    for (const auto& libPair : results) {
        std::cout << "\nnamespace " << libPair.first << " {\n";
        for (const auto& funcPair : libPair.second) {
            if (funcPair.second != 0) {
                std::cout << "\tconst uintptr_t " << funcPair.first << " = REBASE(0x" << std::uppercase << std::hex << funcPair.second <<  ");" << std::dec << "\n";
            }
            else {
               std::cout << "\t// " << funcPair.first << " not found need to do it manually using the sigs \n";
            }
        }
        std::cout << "}\n";
    }

    CloseHandle(hProcess);
    system("pause");
    return 0;
}
