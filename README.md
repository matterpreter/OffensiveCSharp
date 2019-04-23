# OffensiveCSharp
This is a collection of C# tooling and POCs I've created for use on operations. Each project is designed to use no external libraries. Open each project's .SLN in Visual Studio and compile as "Release".


| Project | Description | .NET Version |
| :------ | :---------- | :----------- |
| **AbandonedCOMKeys** | Enumerates abandoned COM keys (specifically `InprocServer32`). Useful for persistence as you can, in some cases, write to the missing location and call with `rundll32.exe -sta {CLSID}`. Technique referenced in [this post](https://bohops.com/2018/06/28/abusing-com-registry-structure-clsid-localserver32-inprocserver32/) by [@bohops](https://twitter.com/bohops) | 4.0 |
| **CredPhisher** | Prompts the current user for their credentials using the `CredUIPromptForWindowsCredentials` WinAPI function. Supports an argument to provide the message text that will be shown to the user. | 3.5 |    
| **EncryptedZIP** | Compresses a directory or file and then encrypts the ZIP file with a supplied key using AES256 CFB. This assembly also clears the key out of memory using `RtlZeroMemory`. Use the included Decrypter progam to decrypt the archive. | 3.5 |  
| **ETWEventSubscription** | Similar to WMI event subscriptions but leverages Event Tracing for Windows. When the event on the system occurs, currently either when any user logs in or a specified process is started, the `DoEvil()` method is executed. | 4.6 |  
| **GPSCoordinates** | Tracks the system's GPS coordinates (accurate within 1km currectly) if Location Services are enabled. Works on Windows 10 currently, but hoping to cover all versions 7+. | 4.0 |
| **ImplantSSP** | Installs a user-supplied Security Support Provider (SSP) DLL on the system, which will be loaded by LSA on system start.  The DLL must export `SpLsaModeInitialize`. Inspired by [Install-SSP](https://powersploit.readthedocs.io/en/latest/Persistence/Install-SSP/) by [@mattifestation](https://twitter.com/mattifestation).  | 3.5 |
| **JunctionFolder** | Creates a junction folder in the Windows Accessories Start Up folder as described in the Vault 7 leaks. On start or when a user browses the directory, the referenced DLL will be executed by `verclsid.exe` in medium integrity. | 3.5 |
| **MockDirUACBypass** | Creates a mock trusted directory, `C:\Windows \System32\`, and moves an auto-elevating Windows executable into the mock directory. A user-supplied DLL which exports the appropriate functions is dropped and when the executable is run, the DLL is loaded and run as high integrity. Technique discovered by [@ce2wells](https://twitter.com/ce2wells) and outlined in [this post.](https://medium.com/tenable-techblog/uac-bypass-by-mocking-trusted-directories-24a96675f6e) | 3.5 |
| **SessionSearcher** | Searches all connected drives for PuTTY private keys and RDP connection files and parses them for relevant details. Based on [SessionGopher](https://github.com/Arvanaghi/SessionGopher) by [@arvanaghi](https://twitter.com/arvanaghi). | 4.0 |
| **UnquotedPath** | Outputs a list of unquoted service paths that aren't in System32/SysWow64 to plant a PE into. [ATT&CK Reference](https://attack.mitre.org/techniques/T1034/) | 3.5 |
