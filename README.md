# Manual Map Injector (C#)

x86 DLL Manual Map injector written in C#. Loads a DLL directly into a target process memory without writing to disk or registering in the PEB module list.

## Features

- Loads DLL from byte array (no disk writes)
- Handles base relocations
- Resolves imports (IAT patching)
- Supports TLS callbacks
- Calls DllMain with DLL_PROCESS_ATTACH
- Cleans up shellcode after injection

## Usage

```csharp
using ManualMapInjector;

var process = Process.GetProcessesByName("target").First();

// From file
Injector.Inject(process, "path/to/dll.dll");

// From bytes (no disk write)
byte[] dllBytes = File.ReadAllBytes("path/to/dll.dll");
Injector.Inject(process, dllBytes);
```

## Requirements

- .NET 6+ or .NET Framework 4.7+
- Target process must be x86 (32-bit)
- Administrator privileges required
- Enable unsafe code: `<AllowUnsafeBlocks>true</AllowUnsafeBlocks>` in .csproj

## How it works

1. Parse PE headers of the DLL
2. Allocate RWX memory in target process
3. Copy PE headers and sections
4. Write shellcode + mapping data to target process
5. Create remote thread to execute shellcode
6. Shellcode handles: relocations → IAT → TLS → DllMain
7. Poll until shellcode writes hMod (completion signal)
8. Clean up shellcode memory

## Credits

Shellcode based on [TheCruZ/Simple-Manual-Map-Injector](https://github.com/TheCruZ/Simple-Manual-Map-Injector) (MIT License)
