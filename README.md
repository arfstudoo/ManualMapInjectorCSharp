# Manual Map Injector (C#)

x86 DLL Manual Map injector written in C#. Loads a DLL directly into target process memory without writing to disk or registering in the PEB module list.

## Features

- Loads DLL from byte array — no disk writes at any point
- Handles base relocations
- Resolves imports (IAT patching inside target process via shellcode)
- Supports TLS callbacks
- Calls DllMain with DLL_PROCESS_ATTACH
- Erases PE header after injection (anti-dump)
- Adjusts section memory protections after injection
- Cleans up shellcode memory after execution

## How it works

```
1. Parse PE headers of the DLL bytes
2. Allocate memory in target process (PAGE_READWRITE → PAGE_EXECUTE_READWRITE)
3. Copy PE headers (first 0x1000 bytes)
4. Copy each section to its virtual address
5. Write MANUAL_MAPPING_DATA struct to target process
6. Write shellcode (0x1000 bytes) to target process
7. CreateRemoteThread → executes shellcode
8. Shellcode (inside target process):
     a. Fix base relocations
     b. Resolve imports via LoadLibraryA + GetProcAddress
     c. Call TLS callbacks
     d. Call DllMain(DLL_PROCESS_ATTACH)
     e. Write hMod to signal completion
9. Poll until shellcode writes hMod
10. Erase PE header (zero out first 0x1000 bytes)
11. Set correct protections per section:
     .text  → PAGE_EXECUTE_READ
     .data  → PAGE_READWRITE
     .rdata → PAGE_READONLY
12. Free shellcode and mapping data memory
```

## Usage

```csharp
using ManualMapInjector;

// From file path
var process = Process.GetProcessesByName("target").First();
bool ok = Injector.Inject(process, @"C:\path\to\dll.dll");

// From byte array (recommended — no disk I/O)
byte[] dllBytes = File.ReadAllBytes(@"C:\path\to\dll.dll");
bool ok = Injector.Inject(process, dllBytes);
```

## Requirements

- .NET 6+ (or .NET Framework 4.7+)
- Target process must be **x86 (32-bit)**
- Run as **Administrator**
- Enable unsafe code in your `.csproj`:

```xml
<AllowUnsafeBlocks>true</AllowUnsafeBlocks>
```

## Roadmap

- [ ] Thread Hijacking instead of CreateRemoteThread
- [ ] x64 support

## Credits

Shellcode extracted from [TheCruZ/Simple-Manual-Map-Injector](https://github.com/TheCruZ/Simple-Manual-Map-Injector) (MIT License)
