using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ManualMapInjector
{
    public static unsafe class Injector
    {
        private static readonly byte[] s_shellcode32 = new byte[]
        {
            0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x54, 0x83, 0x7D, 0x08, 0x00,
            0x75, 0x0F, 0x8B, 0x45, 0x08, 0xC7, 0x40, 0x0C, 0x40, 0x40,
            0x40, 0x00, 0xE9, 0x96, 0x02, 0x00, 0x00, 0x8B, 0x4D, 0x08,
            0x8B, 0x51, 0x08, 0x89, 0x55, 0xF8, 0x8B, 0x45, 0xF8, 0x8B,
            0x48, 0x3C, 0x8B, 0x55, 0xF8, 0x8D, 0x44, 0x0A, 0x18, 0x89,
            0x45, 0xF0, 0x8B, 0x4D, 0x08, 0x8B, 0x11, 0x89, 0x55, 0xB8,
            0x8B, 0x45, 0x08, 0x8B, 0x48, 0x04, 0x89, 0x4D, 0xC8, 0x8B,
            0x55, 0xF0, 0x8B, 0x45, 0xF8, 0x03, 0x42, 0x10, 0x89, 0x45,
            0xAC, 0x8B, 0x4D, 0xF0, 0x8B, 0x55, 0xF8, 0x2B, 0x51, 0x1C,
            0x89, 0x55, 0xD4, 0x0F, 0x84, 0xD9, 0x00, 0x00, 0x00, 0xB8,
            0x08, 0x00, 0x00, 0x00, 0x6B, 0xC8, 0x05, 0x8B, 0x55, 0xF0,
            0x83, 0x7C, 0x0A, 0x64, 0x00, 0x0F, 0x84, 0xC3, 0x00, 0x00,
            0x00, 0xB8, 0x08, 0x00, 0x00, 0x00, 0x6B, 0xC8, 0x05, 0x8B,
            0x55, 0xF0, 0x8B, 0x45, 0xF8, 0x03, 0x44, 0x0A, 0x60, 0x89,
            0x45, 0xF4, 0xB9, 0x08, 0x00, 0x00, 0x00, 0x6B, 0xD1, 0x05,
            0x8B, 0x45, 0xF0, 0x8B, 0x4D, 0xF4, 0x03, 0x4C, 0x10, 0x64,
            0x89, 0x4D, 0xC4, 0x8B, 0x55, 0xF4, 0x3B, 0x55, 0xC4, 0x0F,
            0x83, 0x8D, 0x00, 0x00, 0x00, 0x8B, 0x45, 0xF4, 0x83, 0x78,
            0x04, 0x00, 0x0F, 0x84, 0x80, 0x00, 0x00, 0x00, 0x8B, 0x4D,
            0xF4, 0x8B, 0x51, 0x04, 0x83, 0xEA, 0x08, 0xD1, 0xEA, 0x89,
            0x55, 0xC0, 0x8B, 0x45, 0xF4, 0x83, 0xC0, 0x08, 0x89, 0x45,
            0xDC, 0xC7, 0x45, 0xD8, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x12,
            0x8B, 0x4D, 0xD8, 0x83, 0xC1, 0x01, 0x89, 0x4D, 0xD8, 0x8B,
            0x55, 0xDC, 0x83, 0xC2, 0x02, 0x89, 0x55, 0xDC, 0x8B, 0x45,
            0xD8, 0x3B, 0x45, 0xC0, 0x74, 0x35, 0x8B, 0x4D, 0xDC, 0x0F,
            0xB7, 0x11, 0xC1, 0xFA, 0x0C, 0x83, 0xFA, 0x03, 0x75, 0x25,
            0x8B, 0x45, 0xF4, 0x8B, 0x4D, 0xF8, 0x03, 0x08, 0x8B, 0x55,
            0xDC, 0x0F, 0xB7, 0x02, 0x25, 0xFF, 0x0F, 0x00, 0x00, 0x03,
            0xC8, 0x89, 0x4D, 0xD0, 0x8B, 0x4D, 0xD0, 0x8B, 0x11, 0x03,
            0x55, 0xD4, 0x8B, 0x45, 0xD0, 0x89, 0x10, 0xEB, 0xB1, 0x8B,
            0x4D, 0xF4, 0x8B, 0x55, 0xF4, 0x03, 0x51, 0x04, 0x89, 0x55,
            0xF4, 0xE9, 0x67, 0xFF, 0xFF, 0xFF, 0xB8, 0x08, 0x00, 0x00,
            0x00, 0xC1, 0xE0, 0x00, 0x8B, 0x4D, 0xF0, 0x83, 0x7C, 0x01,
            0x64, 0x00, 0x0F, 0x84, 0xCD, 0x00, 0x00, 0x00, 0xBA, 0x08,
            0x00, 0x00, 0x00, 0xC1, 0xE2, 0x00, 0x8B, 0x45, 0xF0, 0x8B,
            0x4D, 0xF8, 0x03, 0x4C, 0x10, 0x60, 0x89, 0x4D, 0xE8, 0x8B,
            0x55, 0xE8, 0x83, 0x7A, 0x0C, 0x00, 0x0F, 0x84, 0xAB, 0x00,
            0x00, 0x00, 0x8B, 0x45, 0xE8, 0x8B, 0x4D, 0xF8, 0x03, 0x48,
            0x0C, 0x89, 0x4D, 0xBC, 0x8B, 0x55, 0xBC, 0x52, 0xFF, 0x55,
            0xB8, 0x89, 0x45, 0xCC, 0x8B, 0x45, 0xE8, 0x8B, 0x4D, 0xF8,
            0x03, 0x08, 0x89, 0x4D, 0xEC, 0x8B, 0x55, 0xE8, 0x8B, 0x45,
            0xF8, 0x03, 0x42, 0x10, 0x89, 0x45, 0xE4, 0x8B, 0x4D, 0xE8,
            0x83, 0x39, 0x00, 0x75, 0x06, 0x8B, 0x55, 0xE4, 0x89, 0x55,
            0xEC, 0xEB, 0x12, 0x8B, 0x45, 0xEC, 0x83, 0xC0, 0x04, 0x89,
            0x45, 0xEC, 0x8B, 0x4D, 0xE4, 0x83, 0xC1, 0x04, 0x89, 0x4D,
            0xE4, 0x8B, 0x55, 0xEC, 0x83, 0x3A, 0x00, 0x74, 0x46, 0x8B,
            0x45, 0xEC, 0x8B, 0x08, 0x81, 0xE1, 0x00, 0x00, 0x00, 0x80,
            0x74, 0x19, 0x8B, 0x55, 0xEC, 0x8B, 0x02, 0x25, 0xFF, 0xFF,
            0x00, 0x00, 0x50, 0x8B, 0x4D, 0xCC, 0x51, 0xFF, 0x55, 0xC8,
            0x8B, 0x55, 0xE4, 0x89, 0x02, 0xEB, 0x1E, 0x8B, 0x45, 0xEC,
            0x8B, 0x4D, 0xF8, 0x03, 0x08, 0x89, 0x4D, 0xB4, 0x8B, 0x55,
            0xB4, 0x83, 0xC2, 0x02, 0x52, 0x8B, 0x45, 0xCC, 0x50, 0xFF,
            0x55, 0xC8, 0x8B, 0x4D, 0xE4, 0x89, 0x01, 0xEB, 0xA0, 0x8B,
            0x55, 0xE8, 0x83, 0xC2, 0x14, 0x89, 0x55, 0xE8, 0xE9, 0x48,
            0xFF, 0xFF, 0xFF, 0xB8, 0x08, 0x00, 0x00, 0x00, 0x6B, 0xC8,
            0x09, 0x8B, 0x55, 0xF0, 0x83, 0x7C, 0x0A, 0x64, 0x00, 0x74,
            0x49, 0xB8, 0x08, 0x00, 0x00, 0x00, 0x6B, 0xC8, 0x09, 0x8B,
            0x55, 0xF0, 0x8B, 0x45, 0xF8, 0x03, 0x44, 0x0A, 0x60, 0x89,
            0x45, 0xB0, 0x8B, 0x4D, 0xB0, 0x8B, 0x51, 0x0C, 0x89, 0x55,
            0xE0, 0xEB, 0x09, 0x8B, 0x45, 0xE0, 0x83, 0xC0, 0x04, 0x89,
            0x45, 0xE0, 0x83, 0x7D, 0xE0, 0x00, 0x74, 0x1A, 0x8B, 0x4D,
            0xE0, 0x83, 0x39, 0x00, 0x74, 0x12, 0x6A, 0x00, 0x6A, 0x01,
            0x8B, 0x55, 0xF8, 0x52, 0x8B, 0x45, 0xE0, 0x8B, 0x08, 0xFF,
            0xD1, 0x90, 0xEB, 0xD7, 0xC6, 0x45, 0xFF, 0x00, 0x8B, 0x55,
            0x08, 0x8B, 0x42, 0x14, 0x50, 0x8B, 0x4D, 0x08, 0x8B, 0x51,
            0x10, 0x52, 0x8B, 0x45, 0xF8, 0x50, 0xFF, 0x55, 0xAC, 0x90,
            0x0F, 0xB6, 0x4D, 0xFF, 0x85, 0xC9, 0x74, 0x0C, 0x8B, 0x55,
            0x08, 0xC7, 0x42, 0x0C, 0x50, 0x50, 0x50, 0x00, 0xEB, 0x09,
            0x8B, 0x45, 0x08, 0x8B, 0x4D, 0xF8, 0x89, 0x48, 0x0C, 0x8B,
            0xE5, 0x5D, 0xC2, 0x04, 0x00
        };

        public static bool Inject(Process process, byte[] dllBytes)
        {
            if (process == null || process.HasExited)
                throw new Exception("Process is null or has exited");
            if (dllBytes == null || dllBytes.Length < 0x40)
                throw new Exception("Invalid DLL bytes");

            IntPtr hProcess = NativeMethods.OpenProcess(
                NativeMethods.PROCESS_ALL_ACCESS, false, process.Id);
            if (hProcess == IntPtr.Zero)
                throw new Exception($"OpenProcess failed: {Marshal.GetLastWin32Error()}");

            try { return DoManualMap(hProcess, dllBytes); }
            finally { NativeMethods.CloseHandle(hProcess); }
        }

        public static bool Inject(Process process, string dllPath)
            => Inject(process, System.IO.File.ReadAllBytes(dllPath));

        private static bool DoManualMap(IntPtr hProcess, byte[] rawDll)
        {
            fixed (byte* pSrc = rawDll)
            {
                var dos = (IMAGE_DOS_HEADER*)pSrc;
                if (dos->e_magic != 0x5A4D)
                    throw new Exception("Invalid PE: bad MZ");

                var nt = (IMAGE_NT_HEADERS32*)(pSrc + dos->e_lfanew);
                if (nt->Signature != 0x00004550)
                    throw new Exception("Invalid PE: bad signature");
                if (nt->FileHeader.Machine != 0x014C)
                    throw new Exception("Only x86 DLLs supported");

                uint imageSize = nt->OptionalHeader.SizeOfImage;

                IntPtr pTarget = NativeMethods.VirtualAllocEx(
                    hProcess, IntPtr.Zero, imageSize,
                    NativeMethods.MEM_COMMIT | NativeMethods.MEM_RESERVE,
                    NativeMethods.PAGE_READWRITE);

                if (pTarget == IntPtr.Zero)
                    throw new Exception($"VirtualAllocEx(image) failed: {Marshal.GetLastWin32Error()}");

                uint oldp = 0;
                NativeMethods.VirtualProtectEx(hProcess, pTarget, imageSize,
                    NativeMethods.PAGE_EXECUTE_READWRITE, out oldp);

                int hdrLen = Math.Min(0x1000, rawDll.Length);
                byte[] hdrBuf = new byte[hdrLen];
                Array.Copy(rawDll, 0, hdrBuf, 0, hdrLen);
                WriteRemote(hProcess, pTarget, hdrBuf);

                int secOff = dos->e_lfanew + 4
                    + sizeof(IMAGE_FILE_HEADER)
                    + nt->FileHeader.SizeOfOptionalHeader;

                for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
                {
                    var sec = (IMAGE_SECTION_HEADER*)(pSrc + secOff
                              + i * sizeof(IMAGE_SECTION_HEADER));
                    if (sec->SizeOfRawData == 0) continue;
                    if (sec->PointerToRawData + sec->SizeOfRawData > rawDll.Length) continue;

                    byte[] secData = new byte[sec->SizeOfRawData];
                    Array.Copy(rawDll, (int)sec->PointerToRawData,
                               secData, 0, (int)sec->SizeOfRawData);
                    WriteRemote(hProcess,
                        (IntPtr)((long)pTarget + sec->VirtualAddress), secData);
                }

                IntPtr hK32         = NativeMethods.GetModuleHandleA("kernel32.dll");
                IntPtr pLoadLibA    = NativeMethods.GetProcAddress(hK32, "LoadLibraryA");
                IntPtr pGetProcAddr = NativeMethods.GetProcAddress(hK32, "GetProcAddress");

                if (pLoadLibA == IntPtr.Zero || pGetProcAddr == IntPtr.Zero)
                    throw new Exception("Can't get kernel32 exports");

                var mapData = new MANUAL_MAPPING_DATA
                {
                    pLoadLibraryA   = (uint)pLoadLibA,
                    pGetProcAddress = (uint)pGetProcAddr,
                    pbase           = (uint)pTarget,
                    hMod            = 0,
                    fdwReasonParam  = 1,
                    reservedParam   = 0,
                    SEHSupport      = 0
                };

                int dataSize = sizeof(MANUAL_MAPPING_DATA);
                IntPtr pMapData = NativeMethods.VirtualAllocEx(
                    hProcess, IntPtr.Zero, (uint)dataSize,
                    NativeMethods.MEM_COMMIT | NativeMethods.MEM_RESERVE,
                    NativeMethods.PAGE_READWRITE);

                if (pMapData == IntPtr.Zero)
                    throw new Exception($"VirtualAllocEx(data) failed: {Marshal.GetLastWin32Error()}");

                byte[] dataBytes = new byte[dataSize];
                fixed (byte* p = dataBytes)
                    *(MANUAL_MAPPING_DATA*)p = mapData;
                WriteRemote(hProcess, pMapData, dataBytes);

                IntPtr pShell = NativeMethods.VirtualAllocEx(
                    hProcess, IntPtr.Zero, 0x1000,
                    NativeMethods.MEM_COMMIT | NativeMethods.MEM_RESERVE,
                    NativeMethods.PAGE_EXECUTE_READWRITE);

                if (pShell == IntPtr.Zero)
                    throw new Exception($"VirtualAllocEx(shellcode) failed: {Marshal.GetLastWin32Error()}");

                byte[] shellPage = new byte[0x1000];
                Array.Copy(s_shellcode32, 0, shellPage, 0, s_shellcode32.Length);
                WriteRemote(hProcess, pShell, shellPage);

                IntPtr hThread = NativeMethods.CreateRemoteThread(
                    hProcess, IntPtr.Zero, 0,
                    pShell, pMapData, 0, IntPtr.Zero);

                if (hThread == IntPtr.Zero)
                    throw new Exception($"CreateRemoteThread failed: {Marshal.GetLastWin32Error()}");

                NativeMethods.CloseHandle(hThread);

                bool success = false;
                byte[] checkBuf = new byte[dataSize];

                for (int attempt = 0; attempt < 1000; attempt++)
                {
                    System.Threading.Thread.Sleep(10);

                    uint exitCode = 0;
                    NativeMethods.GetExitCodeProcess(hProcess, out exitCode);
                    if (exitCode != 0x103) break;

                    ReadRemote(hProcess, pMapData, checkBuf);
                    uint hMod;
                    fixed (byte* p = checkBuf)
                        hMod = ((MANUAL_MAPPING_DATA*)p)->hMod;

                    if (hMod == 0x404040)
                        throw new Exception("Shellcode: wrong mapping ptr");

                    if (hMod != 0)
                    {
                        success = true;
                        break;
                    }
                }

                byte[] zeros = new byte[0x1000];
                WriteRemote(hProcess, pShell, zeros);
                NativeMethods.VirtualFreeEx(hProcess, pShell,   0, NativeMethods.MEM_RELEASE);
                NativeMethods.VirtualFreeEx(hProcess, pMapData, 0, NativeMethods.MEM_RELEASE);

                if (success)
                {
                    WriteRemote(hProcess, pTarget, new byte[0x1000]);
                    AdjustSectionProtections(hProcess, pTarget, pSrc, secOff,
                        nt->FileHeader.NumberOfSections);
                }

                return success;
            }
        }

        private static unsafe void AdjustSectionProtections(
            IntPtr hProcess, IntPtr pBase, byte* pSrc, int secOff, ushort numSections)
        {
            const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;
            const uint IMAGE_SCN_MEM_READ    = 0x40000000;
            const uint IMAGE_SCN_MEM_WRITE   = 0x80000000;

            for (int i = 0; i < numSections; i++)
            {
                var sec = (IMAGE_SECTION_HEADER*)(pSrc + secOff
                          + i * sizeof(IMAGE_SECTION_HEADER));

                if (sec->Misc_VirtualSize == 0) continue;

                uint chars = sec->Characteristics;
                bool canExec  = (chars & IMAGE_SCN_MEM_EXECUTE) != 0;
                bool canRead  = (chars & IMAGE_SCN_MEM_READ)    != 0;
                bool canWrite = (chars & IMAGE_SCN_MEM_WRITE)   != 0;

                uint protect;
                if (canExec && canWrite)      protect = NativeMethods.PAGE_EXECUTE_READWRITE;
                else if (canExec && canRead)  protect = NativeMethods.PAGE_EXECUTE_READ;
                else if (canExec)             protect = NativeMethods.PAGE_EXECUTE;
                else if (canWrite)            protect = NativeMethods.PAGE_READWRITE;
                else                          protect = NativeMethods.PAGE_READONLY;

                IntPtr secAddr = (IntPtr)((long)pBase + sec->VirtualAddress);
                uint old = 0;
                NativeMethods.VirtualProtectEx(hProcess, secAddr,
                    sec->Misc_VirtualSize, protect, out old);
            }
        }

        private static void WriteRemote(IntPtr hProcess, IntPtr addr, byte[] data)
        {
            uint oldProtect = 0;
            NativeMethods.VirtualProtectEx(hProcess, addr, (uint)data.Length,
                NativeMethods.PAGE_EXECUTE_READWRITE, out oldProtect);

            if (!NativeMethods.WriteProcessMemory(hProcess, addr, data, (uint)data.Length, out _))
                throw new Exception($"WriteProcessMemory @ 0x{addr:X8}: {Marshal.GetLastWin32Error()}");

            if (oldProtect != 0)
                NativeMethods.VirtualProtectEx(hProcess, addr, (uint)data.Length,
                    oldProtect, out _);
        }

        private static void ReadRemote(IntPtr hProcess, IntPtr addr, byte[] buf)
        {
            NativeMethods.ReadProcessMemory(hProcess, addr, buf, (uint)buf.Length, out _);
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct MANUAL_MAPPING_DATA
    {
        public uint pLoadLibraryA;
        public uint pGetProcAddress;
        public uint pbase;
        public uint hMod;
        public uint fdwReasonParam;
        public uint reservedParam;
        public uint SEHSupport;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal unsafe struct IMAGE_DOS_HEADER
    {
        public ushort e_magic;
        public ushort e_cblp, e_cp, e_crlc, e_cparhdr;
        public ushort e_minalloc, e_maxalloc, e_ss, e_sp;
        public ushort e_csum, e_ip, e_cs, e_lfarlc, e_ovno;
        public fixed ushort e_res[4];
        public ushort e_oemid, e_oeminfo;
        public fixed ushort e_res2[10];
        public int e_lfanew;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct IMAGE_FILE_HEADER
    {
        public ushort Machine, NumberOfSections;
        public uint   TimeDateStamp, PointerToSymbolTable, NumberOfSymbols;
        public ushort SizeOfOptionalHeader, Characteristics;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct IMAGE_DATA_DIRECTORY
    {
        public uint VirtualAddress, Size;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal unsafe struct IMAGE_OPTIONAL_HEADER32
    {
        public ushort Magic;
        public byte   MajorLinkerVersion, MinorLinkerVersion;
        public uint   SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
        public uint   AddressOfEntryPoint, BaseOfCode, BaseOfData, ImageBase;
        public uint   SectionAlignment, FileAlignment;
        public ushort MajorOSVersion, MinorOSVersion, MajorImageVersion, MinorImageVersion;
        public ushort MajorSubsystemVersion, MinorSubsystemVersion;
        public uint   Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
        public ushort Subsystem, DllCharacteristics;
        public uint   SizeOfStackReserve, SizeOfStackCommit;
        public uint   SizeOfHeapReserve, SizeOfHeapCommit;
        public uint   LoaderFlags, NumberOfRvaAndSizes;
        public IMAGE_DATA_DIRECTORY D0,  D1,  D2,  D3,  D4,  D5,  D6,  D7;
        public IMAGE_DATA_DIRECTORY D8,  D9,  D10, D11, D12, D13, D14, D15;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct IMAGE_NT_HEADERS32
    {
        public uint                    Signature;
        public IMAGE_FILE_HEADER       FileHeader;
        public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal unsafe struct IMAGE_SECTION_HEADER
    {
        public fixed byte Name[8];
        public uint Misc_VirtualSize, VirtualAddress, SizeOfRawData;
        public uint PointerToRawData, PointerToRelocations, PointerToLinenumbers;
        public ushort NumberOfRelocations, NumberOfLinenumbers;
        public uint Characteristics;
    }

    internal static class NativeMethods
    {
        public const int  PROCESS_ALL_ACCESS     = 0x1F0FFF;
        public const uint MEM_COMMIT             = 0x1000;
        public const uint MEM_RESERVE            = 0x2000;
        public const uint MEM_RELEASE            = 0x8000;
        public const uint PAGE_READONLY          = 0x02;
        public const uint PAGE_READWRITE         = 0x04;
        public const uint PAGE_EXECUTE           = 0x10;
        public const uint PAGE_EXECUTE_READ      = 0x20;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(int access, bool inherit, int pid);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr h);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProc, IntPtr addr,
            uint size, uint type, uint protect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualFreeEx(IntPtr hProc, IntPtr addr,
            uint size, uint type);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtectEx(IntPtr hProc, IntPtr addr,
            uint size, uint newProtect, out uint oldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProc, IntPtr addr,
            byte[] buf, uint size, out UIntPtr written);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProc, IntPtr addr,
            byte[] buf, uint size, out UIntPtr read);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateRemoteThread(IntPtr hProc, IntPtr attr,
            uint stackSize, IntPtr start, IntPtr param, uint flags, IntPtr tid);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetExitCodeProcess(IntPtr hProc, out uint exitCode);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr GetModuleHandleA(string name);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hMod, string name);
    }
}
