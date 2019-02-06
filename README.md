# OffensiveCSharp
This is a collection of C# tooling I've created for use on operations. All code is designed to be compatible with .NET 3.5. Open each project's .SLN in Visual Studio and compile as "Release".

**AbandonedCOMKeys** - Enumerates abandoned COM keys (specifically `InprocServer32`). Useful for persistence as you can, in some cases, write to the missing location and call with `rundll32.exe -sta {CLSID}`. Technique referenced in [this post](https://bohops.com/2018/06/28/abusing-com-registry-structure-clsid-localserver32-inprocserver32/) by @bohops
