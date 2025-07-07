#include "patterns.hpp"

#include <filesystem>
#include <fstream>
#include <cctype>

namespace fs = std::filesystem;
static std::error_code fs_err;

fs::path PATCHES_DIR = "./patches/////////////////////////////////////////////////";

static std::string UnescapeString(const std::string& s) {
    std::string result;
    result.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            char c = s[++i];
            switch (c) {
            case 'n':  result.push_back('\n');  break;
            case 'r':  result.push_back('\r');  break;
            case 't':  result.push_back('\t');  break;
            case '0':  result.push_back('\0');  break;
            case 'x': {
                if (i + 2 < s.size() && std::isxdigit(static_cast<unsigned char>(s[i + 1])) && std::isxdigit(static_cast<unsigned char>(s[i + 2]))) {
                    std::string hexStr = s.substr(i + 1, 2);
                    result.push_back(static_cast<char>(std::stoul(hexStr, nullptr, 16)));
                    i += 2;
                }
                break;
            }
            default:
                // unk escaped char, keep literal..
                result.push_back(c);
            }
        }
        else {
            result.push_back(s[i]);
        }
    }
    return result;
}

bool IsHexString(const std::string& str) {
    if (str.empty()) return false;

    bool hasHex = false;
    for (char ch : str) {
        if (ch == ' ') continue;
        if (!std::isxdigit(static_cast<unsigned char>(ch))) {
            return false;
        }
        hasHex = true;
    }

    return hasHex;
}

std::vector<uint8_t> HexStringToBytes(const std::string& hexStr) {
    std::vector<uint8_t> bytes;
    std::string clean;
    clean.reserve(hexStr.size());

    for (char c : hexStr) if (c != ' ') clean.push_back(c);

    for (size_t i = 0; i + 1 < clean.size(); i += 2) {
        auto byte = static_cast<uint8_t>(std::stoul(clean.substr(i, 2), nullptr, 16));
        bytes.push_back(byte);
    }

    return bytes;
}

bool ReadPatchFile(const fs::path& path, std::string& original, std::string& replacement) {
    std::ifstream file(path);
    if (!file) return false;
    std::getline(file, original);
    std::getline(file, replacement);
    return true;
}

void ApplyPatches() {
    if (!fs::exists(PATCHES_DIR)) fs::create_directory(PATCHES_DIR, fs_err);
    for (auto& entry : fs::directory_iterator(PATCHES_DIR)) {
        if (!entry.is_regular_file()) continue;

        auto orig = std::string();
        auto repl = std::string();
        if (!ReadPatchFile(entry.path(), orig, repl)) continue;

        auto origHex = IsHexString(orig);
        auto replHex = IsHexString(repl);

        auto origData = origHex ? orig : UnescapeString(orig);
        auto replData = replHex ? repl : UnescapeString(repl);

        auto origBytes = origHex ? HexStringToBytes(origData) : std::vector<uint8_t>(origData.begin(), origData.end());
        auto replBytes = replHex ? HexStringToBytes(replData) : std::vector<uint8_t>(replData.begin(), replData.end());

        auto pattern = std::string();
        pattern.reserve(origBytes.size() * 2);
        for (auto b : origBytes) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02X", b);
            pattern += buf;
        }

        auto addresses = patterns::find_patterns(pattern);
        if (addresses.empty()) continue;

        for (auto addr : addresses) {
            size_t origSize = origBytes.size();
            size_t replSize = replBytes.size();
            size_t toWrite = replSize;//std::min(origSize, replSize);

            DWORD oldProtect;
            VirtualProtect(reinterpret_cast<void*>(addr), toWrite, PAGE_EXECUTE_READWRITE, &oldProtect);
            memcpy(reinterpret_cast<void*>(addr), replBytes.data(), toWrite);
            VirtualProtect(reinterpret_cast<void*>(addr), toWrite, oldProtect, &oldProtect);
        }
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        ApplyPatches();
    }
    return TRUE;
}
