#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Psapi.h>
#include <string>
#include <cstdlib>
#include <cstdint>
#include <unordered_map>
#include <type_traits>
#include <patterns.hpp>

// Define pointer size for x86 vs x64
#if defined(_M_X64) || defined(__amd64__)
#  define PTR_SIZE 8
#else
#  define PTR_SIZE 4
#endif

namespace patterns
{
    token_t parse_token(std::string pattern, uint32_t& current_index)
    {
        token_t token;
        token.any_byte = false;
        token.byte = 0;
        token.set_address_cursor = false;
        token.multi_pattern = false;
        token.jump_if_fail = -1;

        if (pattern[current_index] == '?')
        {
            token.any_byte = true;
            current_index++;
        }
        else if (pattern[current_index] == '^')
        {
            token.set_address_cursor = true;
            current_index++;
        }
        else if (pattern[current_index] == '*')
        {
            token.multi_pattern = true;
            current_index++;
        }
        else
        {
            token.byte = std::stoi(pattern.substr(current_index, 2), nullptr, 16);
            current_index += 2;
        }

        return token;
    }

    bool eat_token(char symbol, std::string& pattern, uint32_t& current_index)
    {
        if (pattern[current_index] == symbol)
        {
            current_index++;
            return true;
        }
        return false;
    }

    std::vector<token_t> parse_pattern(std::string pattern)
    {
        uint32_t current_index = 0;
        std::vector<token_t> tokens;

        while (current_index < pattern.length())
        {
            if (pattern[current_index] == ' ')
            {
                current_index++;
                continue;
            }
            else if (eat_token('[', pattern, current_index))
            {
                std::vector<token_t> sub_tokens;
                while (!eat_token(']', pattern, current_index))
                {
                    token_t token = parse_token(pattern, current_index);
                    sub_tokens.push_back(token);
                }
                int32_t len = (int32_t)sub_tokens.size();
                for (int32_t i = 0; i < (int32_t)sub_tokens.size(); i++)
                {
                    sub_tokens[i].jump_if_fail = len - i - 1;
                }
                tokens.insert(tokens.end(), sub_tokens.begin(), sub_tokens.end());
                continue;
            }

            token_t token = parse_token(pattern, current_index);
            tokens.push_back(token);
        }

        return tokens;
    }

    int8_t read_signed_byte(std::string& pattern, uint32_t& current_index)
    {
        bool is_negative = false;
        switch (pattern[current_index])
        {
        case '+':
            current_index++;
            break;
        case '-':
            is_negative = true;
            current_index++;
            break;
        default:
            break;
        }

        int8_t byte = std::stoi(pattern.substr(current_index, 2), nullptr, 16);
        if (is_negative)
            byte = -byte;
        current_index += 2;
        return byte;
    }

    std::vector<byte_t> parse_mask(std::string mask)
    {
        uint32_t current_index = 0;
        std::vector<byte_t> bytes;
        uint32_t repeat_count = 1;

        while (current_index < mask.length())
        {
            byte_t byte{};
            byte.any_byte = false;
            byte.is_relative = false;
            byte.is_address = false;
            byte.value = 0;
            byte.offset = 0;

            if (mask[current_index] == ' ')
            {
                current_index++;
            }
            else if (mask[current_index] == '?')
            {
                byte.any_byte = true;
                current_index++;
            }
            else if (mask[current_index] == '%')
            {
                byte.is_relative = true;
                eat_token('(', mask, ++current_index);
                byte.value = read_signed_byte(mask, current_index);
                eat_token(')', mask, current_index);
            }
            else if (mask[current_index] == '$')
            {
                byte.is_address = true;
                eat_token('(', mask, ++current_index);
                byte.offset = read_signed_byte(mask, current_index);
                eat_token(')', mask, current_index);
            }
            else if (mask[current_index] == '&')
            {
                byte.is_address = true;
                byte.is_relative = true;
                eat_token('(', mask, ++current_index);
                byte.offset = read_signed_byte(mask, current_index);
                byte.value = read_signed_byte(mask, current_index);
                eat_token(')', mask, current_index);
            }
            else if (mask[current_index] == '*')
            {
                eat_token('(', mask, ++current_index);
                repeat_count = std::stoi(mask.substr(current_index, 2), nullptr, 16);
                current_index += 2;
                eat_token(')', mask, current_index);
                continue;
            }
            else if (mask[current_index] == '@')
            {
                byte.is_pattern = true;
                uint8_t bytes_to_store = std::stoi(mask.substr(++current_index, 1), nullptr, 10);
                eat_token('(', mask, ++current_index);
                std::string pat;
                while (!eat_token(')', mask, current_index))
                {
                    pat += mask[current_index++];
                }
                byte.value = bytes_to_store;
                byte.pattern = pat;
            }
            else
            {
                byte.value = std::stoi(mask.substr(current_index, 2), nullptr, 16);
                current_index += 2;
            }

            for (uint32_t i = 0; i < repeat_count; i++)
                bytes.push_back(byte);
            repeat_count = 1;
        }

        return bytes;
    }

    std::vector<uintptr_t> find_pattern(std::vector<token_t> pattern, std::string library)
    {
        // get module handle
        HMODULE module = library.empty() ? GetModuleHandle(nullptr) : GetModuleHandle(library.c_str());
        if (!module) return {};

        bool search_all = false;
        if (!pattern.empty() && pattern[0].multi_pattern)
        {
            search_all = true;
            pattern.erase(pattern.begin());
        }

        MODULEINFO module_info;
        if (!GetModuleInformation(GetCurrentProcess(), module, &module_info, sizeof(module_info)))
            return {};

        std::vector<uintptr_t> addresses;

        // iterate over module memory with 64-bit index
        for (SIZE_T i = 0; i < module_info.SizeOfImage; ++i)
        {
            bool found = true;
            void* base = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(module) + i);
            bool set_address_cursor = false;
            SIZE_T subtracted_bytes = 0;
            SIZE_T max_jump_length = SIZE_MAX;

            for (SIZE_T j = 0; j < pattern.size(); ++j)
            {
                if (pattern[j].set_address_cursor)
                {
                    base = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(module) + i + j);
                    set_address_cursor = true;
                    continue;
                }
                uintptr_t addr = reinterpret_cast<uintptr_t>(module) + i + (set_address_cursor ? j - 1 : j) - subtracted_bytes;
                if (addr >= reinterpret_cast<uintptr_t>(module) + module_info.SizeOfImage)
                {
                    found = false;
                    break;
                }
                if (pattern[j].jump_if_fail != -1 && max_jump_length == SIZE_MAX)
                    max_jump_length = pattern[j].jump_if_fail;
                else if (pattern[j].jump_if_fail == -1)
                    max_jump_length = SIZE_MAX;

                if (!pattern[j].any_byte && *reinterpret_cast<uint8_t*>(addr) != pattern[j].byte)
                {
                    if (pattern[j].jump_if_fail != -1)
                    {
                        j += pattern[j].jump_if_fail;
                        subtracted_bytes += max_jump_length + 1;
                        continue;
                    }
                    found = false;
                    break;
                }
            }

            if (found)
            {
                if (search_all)
                    addresses.push_back(i);
                else
                    return { i };
            }
        }

        return addresses;
    }

    std::vector<uintptr_t> find_patterns(std::string pattern, std::string library)
    {
        auto tokens = parse_pattern(pattern);
        return find_pattern(tokens, library);
    }

    uintptr_t find_pattern(std::string pattern, std::string library)
    {
        auto results = find_patterns(pattern, library);
        return results.empty() ? 0 : results[0];
    }

    result_t match(std::string pattern, std::string library, std::string mask)
    {
        result_t result; result.found = false;
        auto tokens = parse_pattern(pattern);
        auto bytes = parse_mask(mask);
        auto addresses = find_pattern(tokens, library);
        if (addresses.empty()) return result;
        result.found = true;

        uintptr_t module_addr = reinterpret_cast<uintptr_t>(GetModuleHandle(library.empty() ? nullptr : library.c_str()));
        for (auto address : addresses)
        {
            opcode_t opcode;
            opcode.address = reinterpret_cast<void*>(address);
            SIZE_T global_offset = 0;

            for (SIZE_T i = 0; i < bytes.size(); ++i)
            {
                uintptr_t curr = address + i + global_offset;
                uint8_t b = *reinterpret_cast<uint8_t*>(curr);
                opcode.off_bytes.push_back(b);

                if (bytes[i].any_byte)
                {
                    opcode.on_bytes.push_back(b);
                }
                else if (bytes[i].is_relative && bytes[i].is_address)
                {
                    uintptr_t raw = *reinterpret_cast<uintptr_t*>(curr + bytes[i].offset);
                    opcode.on_bytes.push_back(static_cast<uint8_t>(raw + bytes[i].value));
                }
                else if (bytes[i].is_relative)
                {
                    opcode.on_bytes.push_back(b + bytes[i].value);
                }
                else if (bytes[i].is_address)
                {
                    uintptr_t raw = *reinterpret_cast<uintptr_t*>(curr + bytes[i].offset);
                    for (int k = 0; k < PTR_SIZE; ++k)
                        opcode.on_bytes.push_back(static_cast<uint8_t>((raw >> (k * 8)) & 0xFF));
                }
                else if (bytes[i].is_pattern)
                {
                    uintptr_t addr = find_pattern(bytes[i].pattern, library);
                    uintptr_t offset = addr - (curr);
                    offset -= bytes[i].value;
                    for (uint32_t j = 0; j < bytes[i].value; ++j)
                    {
                        uintptr_t loc = address + i + global_offset + j;
                        uint8_t bb = *reinterpret_cast<uint8_t*>(loc);
                        if (j > 0) opcode.off_bytes.push_back(bb);
                        opcode.on_bytes.push_back(static_cast<uint8_t>((offset >> (j * 8)) & 0xFF));
                    }
                    global_offset += bytes[i].value;
                }
                else
                {
                    opcode.on_bytes.push_back(bytes[i].value);
                }
            }
            result.opcodes.push_back(opcode);
        }

        return result;
    }
}
