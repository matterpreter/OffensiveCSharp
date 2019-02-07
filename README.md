# OffensiveCSharp
This is a collection of C# tooling I've created for use on operations. All code is designed to be compatible with .NET 3.5 unless otherwise noted. Open each project's .SLN in Visual Studio and compile as "Release".

**AbandonedCOMKeys** - Enumerates abandoned COM keys (specifically `InprocServer32`). Useful for persistence as you can, in some cases, write to the missing location and call with `rundll32.exe -sta {CLSID}`. Technique referenced in [this post](https://bohops.com/2018/06/28/abusing-com-registry-structure-clsid-localserver32-inprocserver32/) by @bohops  
**CredPhisher** - Prompts the current user for their credentials using the `CredUIPromptForWindowsCredentials` WinAPI function. Supports an argument to provide the message text that will be shown to the user.  
**GPSCoordinates (.NET 4.0+)** - Gets the system's current GPS coordinates (accurate within 1km currectly) if Location Services are enabled. Works on Windows 10 currently, but hoping to cover all versions 7+.  
