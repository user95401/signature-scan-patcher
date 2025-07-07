Automatically applies binary patches when injected into a process. Reads patch files from `./patches/` and modifies memory at runtime.

### How It Works
1. **DLL Load**: Patches trigger on `DLL_PROCESS_ATTACH`
2. **Patch Files**: Scans `./patches/*` for text files
3. **Pattern Matching**: Finds memory addresses using hex patterns
4. **Hot Patching**: Overwrites process memory (with PAGE_EXECUTE_READWRITE)

### Patch File Format  
Each patch file **must** contain exactly two lines:  
1. **Original Pattern** (what to search for)  
2. **Replacement** (what to overwrite with)

Any other lines you can use as you want. They are ignored.

#### Supported Formats:  
| Type        | Example                     | Description                  |  
|-------------|-----------------------------|------------------------------|  
| **Hex**     | `"DE AD BE EF"`             | Space-separated hex bytes    |  
| **Text**    | `"Hello\\nWorld\\x00"`      | C-style escaped characters   |  

#### Escaped Sequences Supported:  
- `\n` -> Newline
- `\t` -> Tab
- `\0` -> Null byte
- `\x41` -> Hex byte `0x41` ("A")

### Usage Example  
1. Create patch file `./patches/disable_analytics.txt`:  
```text
8B 45 08 85 C0 74 0A    // Original pattern (hex bytes of instruction)
90 90 90 90 90 90       // Replacement (NOPs to skip check)  
```

2. Inject release of this project into target process
3. DLL automatically:
   - Scans memory for `8B450885C0740A`
   - Overwrites with `909090909090`

### Key Features
- **Auto Hex Detection**: Uses hex if line contains only `[0-9A-Fa-f ]`, else unescaped string
- **Multi-Match Support**: Patches all found addresses
- **No External Tools**: Pure C++ with WinAPI memory ops

### Sample Patch Scenarios
#### Case 1: Some Bypass
**File**: `./patches/skip_license.txt`
```text
74 0A 80 7D FC 00
EB 0A 80 7D FC 00
```
*(Changes `JZ` to `JMP`)*

#### Case 2: Modify String
**File**: `./patches/change_welcome.txt`
```text
Welcome to Trial Version\x00
Welcome to PRO Version\x00
```

#### Case 3: Mixed Binary/String Patch
**File**: `./patches/mixed_patch.txt`
```text
A1 A2 0A 20 20 85 C0
\x90\x90\x90Hacked!\x00
```


# String data replace showcase:
![image](https://github.com/user-attachments/assets/b1310321-f89b-4d6e-8cf8-bcc34fcdb277)
