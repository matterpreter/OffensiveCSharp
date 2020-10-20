using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace HijackHunter
{
    internal static unsafe class UnsafeHelpers
    {
        #region Methods
        public static unsafe string GetPeArchitecture(byte[] fileBytes)
        {
            // GetPeArchitecture takes the file and checks the Machine Type to
            // make sure the file is either x86 or x64, which are the only 2
            // file architectures we can deal with
            fixed (byte* ptr_data = fileBytes)
            {
                // Get the DOS header
                IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)ptr_data;

                // Get the NT header using e_lfanew
                IMAGE_NT_HEADERS64* nt_header = (IMAGE_NT_HEADERS64*)(ptr_data + dos_header->e_lfanew);

                // Get the image architecture. We only want x86 and x64.
                if (nt_header->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
                {
                    return "x64";
                }
                else if (nt_header->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
                {
                    return "x86";
                }
                else { return null; }
            }
        }

        public static unsafe List<uint> GetStaticImportNameOffsets(byte[] fileBytes, string arch)
        {
            // This function walks the PE header to get the offset of the Import Address Table
            // (IAT) and then resolves the imports' names
            fixed (byte* ptr_data = fileBytes)
            {
                // Initial validation
                UnsafeHelpers.IMAGE_DOS_HEADER* dos_header = (UnsafeHelpers.IMAGE_DOS_HEADER*)ptr_data;
                if (dos_header->e_magic != UnsafeHelpers.IMAGE_DOS_SIGNATURE)
                {
                    Console.WriteLine("[-] Magic bytes don't match");
                    return null;
                }

                // We'll split here because much of the work we need to do uses offsets from the NT headers
                if (arch == "x64")
                {
                    UnsafeHelpers.IMAGE_NT_HEADERS64* nt_header = (UnsafeHelpers.IMAGE_NT_HEADERS64*)(ptr_data + dos_header->e_lfanew);
                    if (nt_header->Signature != UnsafeHelpers.IMAGE_NT_SIGNATURE)
                    {
                        Console.WriteLine("[-] NT Header signature mismatch");
                        return null;
                    }
                    IMAGE_DATA_DIRECTORY* DataDirectory = (IMAGE_DATA_DIRECTORY*)(&nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);

                    // Safety check in case others fail. This will happen on x86 EXEs and some .NET assemblies.
                    uint itRVA = DataDirectory->VirtualAddress;
                    if (itRVA == 0)
                    {
                        Console.WriteLine("[!] Import Table RVA is 0. Something is wrong...");
                        return null;
                    }

                    // Do the conversion from the RVA to the offsets we'll need to do some math
                    Offset iatOffsets = RvaToOffset(nt_header, null, itRVA, "IAT");

                    // Math to get the true offset to the name of the DLL
                    // https://ired.team/miscellaneous-reversing-forensics/pe-file-header-parser-in-c++#pimage_import_descriptor
                    uint offset = iatOffsets.RawOffset + (itRVA - iatOffsets.RVA);
                    UnsafeHelpers.IMAGE_IMPORT_DESCRIPTOR* firstModule = (UnsafeHelpers.IMAGE_IMPORT_DESCRIPTOR*)(ptr_data + offset);

                    List<uint> nameOffsets = new List<uint>();
                    while (firstModule->Name != 0)
                    {
                        uint trueOffset = 0 + iatOffsets.RawOffset + (firstModule->Name - iatOffsets.RVA);
                        nameOffsets.Add(trueOffset);
                        firstModule++;
                    }

                    return nameOffsets;
                }
                else // x86
                {
                    UnsafeHelpers.IMAGE_NT_HEADERS32* nt_header = (UnsafeHelpers.IMAGE_NT_HEADERS32*)(ptr_data + dos_header->e_lfanew);
                    if (nt_header->Signature != UnsafeHelpers.IMAGE_NT_SIGNATURE)
                    {
                        Console.WriteLine("[-] NT Header signature mismatch");
                        return null;
                    }
                    UnsafeHelpers.IMAGE_DATA_DIRECTORY* DataDirectory = (UnsafeHelpers.IMAGE_DATA_DIRECTORY*)(&nt_header->OptionalHeader.DataDirectory[UnsafeHelpers.IMAGE_DIRECTORY_ENTRY_IMPORT]);

                    // Safety check in case others fail. This will happen on x86 EXEs and some .NET assemblies.
                    uint itRVA = DataDirectory->VirtualAddress;
                    if (itRVA == 0)
                    {
                        Console.WriteLine("[!] Import Table RVA is 0. Something is wrong...");
                        return null;
                    }

                    // Do the conversion from the RVA to the offsets we'll need to do some math
                    Offset iatOffsets = RvaToOffset(null, nt_header, itRVA, "IAT");

                    // Math to get the true offset to the name of the DLL
                    // https://ired.team/miscellaneous-reversing-forensics/pe-file-header-parser-in-c++#pimage_import_descriptor
                    uint offset = iatOffsets.RawOffset + (itRVA - iatOffsets.RVA);
                    UnsafeHelpers.IMAGE_IMPORT_DESCRIPTOR* firstModule = (UnsafeHelpers.IMAGE_IMPORT_DESCRIPTOR*)(ptr_data + offset);

                    //uint nameOffset = 0 + rdataRawOffset + (firstModule->Name - rdataRVA);

                    List<uint> nameOffsets = new List<uint>();
                    while (firstModule->Name != 0)
                    {
                        uint trueOffset = 0 + iatOffsets.RawOffset + (firstModule->Name - iatOffsets.RVA);
                        nameOffsets.Add(trueOffset);
                        firstModule++;
                    }

                    return nameOffsets;

                }
            }
        }

        public static List<string> GetStaticImports(byte[] fileBytes, string arch)
        {
            List<uint> offsets = GetStaticImportNameOffsets(fileBytes, arch);
            List<string> dllNames = new List<string>();

            foreach (uint offset in offsets)
            {
                byte[] nameBase = new byte[fileBytes.Length - offset];
                Array.Copy(fileBytes, offset, nameBase, 0, fileBytes.Length - offset);
                string name = Encoding.ASCII.GetString(nameBase, 0, nameBase.Length);
                int i = name.IndexOf('\0');
                if (i >= 0) name = name.Substring(0, i);
                dllNames.Add(name);
            }

            return dllNames;
        }

        public static unsafe List<string> GetDynamicImports(byte[] fileBytes, string arch)
        {
            // This function walks the PE header to get the offset of the Delay-Load Descriptor Table
            // (DLDT) and then resolves the imports' names
            List<string> dynamicModuleNames = new List<string>();
            fixed (byte* ptr_data = fileBytes)
            {
                // Initial validation
                UnsafeHelpers.IMAGE_DOS_HEADER* dos_header = (UnsafeHelpers.IMAGE_DOS_HEADER*)ptr_data;
                if (dos_header->e_magic != UnsafeHelpers.IMAGE_DOS_SIGNATURE)
                {
                    Console.WriteLine("[-] Magic bytes don't match");
                    return dynamicModuleNames;
                }

                // Get the NT headers
                if (arch == "x64")
                {
                    IMAGE_NT_HEADERS64* nt_header = (IMAGE_NT_HEADERS64*)(ptr_data + dos_header->e_lfanew);
                    if (nt_header->Signature != IMAGE_NT_SIGNATURE)
                    {
                        Console.WriteLine("[-] NT Header signature mismatch");
                        return dynamicModuleNames;
                    }

                    // Get the offset for the delay-load import tables
                    ulong* DataDirectory = nt_header->OptionalHeader.DataDirectory;
                    IMAGE_DATA_DIRECTORY* dldt = (IMAGE_DATA_DIRECTORY*)(&nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]);
                    uint dldtRVA = dldt->VirtualAddress;
                    if (dldtRVA == 0) // No delayed imports found
                    {
                        return dynamicModuleNames;
                    }

                    Offset offsets = RvaToOffset(nt_header, null, dldtRVA, "DLDT");
                    uint offset = offsets.RawOffset + (dldtRVA - offsets.RVA);

                    // Iterate over the list of delay-loaded modules
                    IMAGE_DELAY_IMPORT_DESCRIPTOR* firstModule = (UnsafeHelpers.IMAGE_DELAY_IMPORT_DESCRIPTOR*)(ptr_data + offset);

                    while (firstModule->szName != 0)
                    {
                        Offset offsetToNames = RvaToOffset(nt_header, null, firstModule->szName, "szName");
                        uint offset2 = offsetToNames.RawOffset + (firstModule->szName - offsetToNames.RVA);
                        dynamicModuleNames.Add(Marshal.PtrToStringAnsi((IntPtr)(ptr_data + offset2)));
                        firstModule = (UnsafeHelpers.IMAGE_DELAY_IMPORT_DESCRIPTOR*)((long)firstModule + (long)Marshal.SizeOf(typeof(UnsafeHelpers.IMAGE_DELAY_IMPORT_DESCRIPTOR)));
                    }
                }
                else // x86
                {
                    IMAGE_NT_HEADERS32* nt_header = (IMAGE_NT_HEADERS32*)(ptr_data + dos_header->e_lfanew);
                    if (nt_header->Signature != IMAGE_NT_SIGNATURE)
                    {
                        Console.WriteLine("[-] NT Header signature mismatch");
                        return dynamicModuleNames;
                    }

                    // Get the offset for the delay-load import tables
                    ulong* DataDirectory = nt_header->OptionalHeader.DataDirectory;
                    IMAGE_DATA_DIRECTORY* dldt = (IMAGE_DATA_DIRECTORY*)(&nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]);
                    uint dldtRVA = dldt->VirtualAddress;
                    if (dldtRVA == 0) // No delayed imports found
                    {
                        return dynamicModuleNames;
                    }

                    Offset offsets = RvaToOffset(null, nt_header, dldtRVA, "DLDT");
                    uint offset = offsets.RawOffset + (dldtRVA - offsets.RVA);

                    // Iterate over the list of delay-loaded modules
                    IMAGE_DELAY_IMPORT_DESCRIPTOR* firstModule = (IMAGE_DELAY_IMPORT_DESCRIPTOR*)(ptr_data + offset);

                    while (firstModule->szName != 0)
                    {
                        Offset offsetToNames = RvaToOffset(null, nt_header, firstModule->szName, "szName");
                        uint offset2 = offsetToNames.RawOffset + (firstModule->szName - offsetToNames.RVA);
                        dynamicModuleNames.Add(Marshal.PtrToStringAnsi((IntPtr)(ptr_data + offset2)));
                        firstModule = (IMAGE_DELAY_IMPORT_DESCRIPTOR*)((long)firstModule + (long)Marshal.SizeOf(typeof(UnsafeHelpers.IMAGE_DELAY_IMPORT_DESCRIPTOR)));
                    }
                }

                return dynamicModuleNames;
            }
        }

        public static unsafe Offset RvaToOffset(IMAGE_NT_HEADERS64* nt64, IMAGE_NT_HEADERS32* nt32, uint rva, string friendlyName)
        {
            Offset offsets = new Offset();

            if (nt64 != null) // x64
            {
                IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION((byte*)nt64);
                for (int i = 1; i < nt64->FileHeader.NumberOfSections + 1; i++)
                {
                    if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->SizeOfRawData)
                    {
                        offsets.RVA = section->VirtualAddress;
                        offsets.RawOffset = section->PointerToRawData;
                    }

                    section = (IMAGE_SECTION_HEADER*)((long)section + (long)Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)));
                }
                uint offset = offsets.RawOffset + (rva - offsets.RVA);

                return offsets;
            }
            else if (nt32 != null) // x86
            {
                IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION((byte*)nt32);
                for (int i = 1; i < nt32->FileHeader.NumberOfSections + 1; i++)
                {
                    if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->SizeOfRawData)
                    {
                        offsets.RVA = section->VirtualAddress;
                        offsets.RawOffset = section->PointerToRawData;
                    }
                    section = (IMAGE_SECTION_HEADER*)((long)section + (long)Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)));
                }

                uint offset = offsets.RawOffset + (rva - offsets.RVA);

                return offsets;
            }
            else
            {
                return offsets;
            }
        }

        public static IMAGE_SECTION_HEADER* IMAGE_FIRST_SECTION(byte* ptr_image_nt_headers)
        {
            if (Environment.Is64BitProcess)
            {
                IMAGE_NT_HEADERS64* image_nt_headers = (IMAGE_NT_HEADERS64*)ptr_image_nt_headers;
                return (IMAGE_SECTION_HEADER*)((long)image_nt_headers +
                                               (long)Marshal.OffsetOf(typeof(IMAGE_NT_HEADERS64), "OptionalHeader") +
                                               image_nt_headers->FileHeader.SizeOfOptionalHeader);
            }
            else
            {
                IMAGE_NT_HEADERS32* image_nt_headers = (IMAGE_NT_HEADERS32*)ptr_image_nt_headers;
                return (IMAGE_SECTION_HEADER*)((long)image_nt_headers +
                                               (long)Marshal.OffsetOf(typeof(IMAGE_NT_HEADERS32), "OptionalHeader") +
                                               image_nt_headers->FileHeader.SizeOfOptionalHeader);
            }
        }
        #endregion

        #region Structures

        #region IMAGE_DOS_HEADER
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_DOS_HEADER                         // DOS .EXE header
        {
            public ushort e_magic;                      // Magic number
            public ushort e_cblp;                       // Bytes on last page of file
            public ushort e_cp;                         // Pages in file
            public ushort e_crlc;                       // Relocations
            public ushort e_cparhdr;                    // Size of header in paragraphs
            public ushort e_minalloc;                   // Minimum extra paragraphs needed
            public ushort e_maxalloc;                   // Maximum extra paragraphs needed
            public ushort e_ss;                         // Initial (relative) SS value
            public ushort e_sp;                         // Initial SP value
            public ushort e_csum;                       // Checksum
            public ushort e_ip;                         // Initial IP value
            public ushort e_cs;                         // Initial (relative) CS value
            public ushort e_lfarlc;                     // File address of relocation table
            public ushort e_ovno;                       // Overlay number
            public fixed ushort e_res[4];               // Reserved ushorts
            public ushort e_oemid;                      // OEM identifier (for e_oeminfo)
            public ushort e_oeminfo;                    // OEM information; e_oemid specific
            public fixed ushort e_res2[10];             // Reserved ushorts
            public uint e_lfanew;                       // File address of new exe header
        }
        #endregion

        #region IMAGE_NT_HEADERS32

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_NT_HEADERS32
        {
            public uint Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
        }

        #endregion

        #region IMAGE_NT_HEADERS64

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_NT_HEADERS64
        {
            public uint Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        }

        #endregion

        #region IMAGE_FILE_HEADER

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_FILE_HEADER
        {
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        #endregion

        #region IMAGE_OPTIONAL_HEADER32

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            public ushort Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public uint BaseOfData;
            public uint ImageBase; // Converted from IntPtr to fix alignment
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public uint SizeOfStackReserve;
            public uint SizeOfStackCommit;
            public uint SizeOfHeapReserve;
            public uint SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
            public fixed ulong DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
        }

        #endregion

        #region IMAGE_OPTIONAL_HEADER64

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            public ushort Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public ulong ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public ulong SizeOfStackReserve;
            public ulong SizeOfStackCommit;
            public ulong SizeOfHeapReserve;
            public ulong SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
            public fixed ulong DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
        }

        #endregion

        #region IMAGE_DATA_DIRECTORY

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress;
            public uint Size;
        }

        #endregion

        #region IMAGE_IMPORT_DESCRIPTOR

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_IMPORT_DESCRIPTOR
        {
            public uint Characteristics;
            public uint TimeDateStamp;
            public uint ForwarderChain;
            public uint Name;
            public uint FirstThunk;
        }

        #endregion

        #region IMAGE_SECTION_HEADER

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_SECTION_HEADER
        {
            public fixed byte Name[IMAGE_SIZEOF_SHORT_NAME];
            public uint PhysicalAddress;
            public uint VirtualAddress;
            public uint SizeOfRawData;
            public uint PointerToRawData;
            public uint PointerToRelocations;
            public uint PointerToLinenumbers;
            public ushort NumberOfRelocations;
            public ushort NumberOfLinenumbers;
            public uint Characteristics;
        }

        #endregion

        #region IMAGE_DELAY_IMPORT_DESCRIPTOR
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_DELAY_IMPORT_DESCRIPTOR
        {
            public uint grAttrs;
            public uint szName;
            public uint phmod;
            public uint pIAT;
            public uint pINT;
            public uint pBoundIAT;
            public uint pUnloadIAT;
            public uint dwTimeStamp;
        }
        #endregion

        #region Offset
        internal struct Offset
        {
            public uint RVA;
            public uint RawOffset;
        }
        #endregion

        #endregion

        #region Constants
        public const int IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;

        public const int IMAGE_SIZEOF_SHORT_NAME = 8;

        public const ushort IMAGE_FILE_MACHINE_I386 = 0x014c;
        public const ushort IMAGE_FILE_MACHINE_AMD64 = 0x8664;

        public const uint IMAGE_DOS_SIGNATURE = 0x5A4D;      // MZ
        public const uint IMAGE_NT_SIGNATURE = 0x00004550;  // PE00

        public const int IMAGE_DIRECTORY_ENTRY_IMPORT = 1;            // Import Directory
        public const int IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13;     // Delay Load Import Descriptors

        #endregion
    }
}