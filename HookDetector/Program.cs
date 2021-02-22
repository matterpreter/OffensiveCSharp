using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Linq;
using System.Collections.Generic;

namespace HookDetector
{
    class Program
    {
        static string[] functions =
        {
            "NtClose",
            "NtAllocateVirtualMemory",
            "NtAllocateVirtualMemoryEx",
            "NtCreateThread",
            "NtCreateThreadEx",
            "NtCreateUserProcess",
            "NtFreeVirtualMemory",
            "NtLoadDriver",
            "NtMapViewOfSection",
            "NtOpenProcess",
            "NtProtectVirtualMemory",
            "NtQueueApcThread",
            "NtQueueApcThreadEx",
            "NtResumeThread",
            "NtSetContextThread",
            "NtSetInformationProcess",
            "NtSuspendThread",
            "NtUnloadDriver",
            "NtWriteVirtualMemory"
        };
        static byte[] safeBytes = {
            0x4c, 0x8b, 0xd1, // mov r10, rcx
            0xb8              // mov eax, ??
        };

        static void Main()
        {
            if (!GetProcessArch())
            {
                Console.WriteLine("[-] It looks like you're not running x64.");
                return;
            }
            // Get the base address of ntdll.dll in our own process
            IntPtr ntdllBase = GetNTDLLBase();
            if (ntdllBase == IntPtr.Zero)
            {
                Console.WriteLine("[-] Couldn't get find ntdll.dll");
                return;

            }
            else { Console.WriteLine("NTDLL Base Address: 0x{0:X}", ntdllBase.ToInt64()); }

            // Get the address of each of the target functions in ntdll.dll
            IDictionary<string, IntPtr> funcAddresses = GetFuncAddress(ntdllBase, functions);

            // Check the first DWORD at each function's address for proper SYSCALL setup
            int i = 0; // Used for populating the results array
            bool safe;
            foreach (KeyValuePair<string, IntPtr> func in funcAddresses)
            {
                byte[] instructions = new byte[4];
                Marshal.Copy(func.Value, instructions, 0, 4);

                string fmtFunc = string.Format("    {0,-25} 0x{1:X} ", func.Key, func.Value.ToInt64());
                safe = instructions.SequenceEqual(safeBytes);

                if (safe)
                {
                    Console.WriteLine(fmtFunc + "- SAFE");
                }
                else
                {
                    byte[] hookInstructions = new byte[32];
                    Marshal.Copy(func.Value, hookInstructions, 0, 32);
                    Console.WriteLine(fmtFunc + " - HOOK DETECTED");
                    Console.WriteLine("    {0,-25} {1}", "Instructions: ", BitConverter.ToString(hookInstructions).Replace("-", " "));
                }

                i++;
            }

        }

        static IntPtr GetNTDLLBase()
        {
            Process hProc = Process.GetCurrentProcess();
            ProcessModule module = hProc.Modules.Cast<ProcessModule>().SingleOrDefault(m => string.Equals(m.ModuleName, "ntdll.dll", StringComparison.OrdinalIgnoreCase));
            return module?.BaseAddress ?? IntPtr.Zero;
        }

        static IDictionary<string, IntPtr> GetFuncAddress(IntPtr hModule, string[] functions)
        {
            IDictionary<string, IntPtr> funcAddresses = new Dictionary<string, IntPtr>();
            foreach (string function in functions)
            {
                IntPtr funcPtr = Win32.GetProcAddress(hModule, function);
                if (funcPtr != IntPtr.Zero)
                {
                    funcAddresses.Add(function,funcPtr);
                }
                else
                {
                    Console.WriteLine("[-] Couldn't locate the address for {0}! (Error: {1})", function, Marshal.GetLastWin32Error());
                }
            }

            return funcAddresses;
        }

        static bool GetProcessArch()
        {
            // Make sure that we're running x64 on x64
            bool wow64;
            Win32.IsWow64Process(Process.GetCurrentProcess().Handle, out wow64);

            if (Environment.Is64BitProcess && !wow64)
            {
                return true;
            }
            else
            {
                return false;
            }

        }
    }

    class Win32
    {
        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        public static extern bool IsWow64Process(IntPtr hProcess, out bool Wow64Process);
    }
}