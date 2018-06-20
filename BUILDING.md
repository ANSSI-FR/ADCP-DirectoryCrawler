# Building Directorycrawler

## Supported compilers
* Visual Studio 2017 with any Windows 10 SDK

## Supported platforms
* x86 (platform Win32)
* x86_64 (platform x64)

## Build DirectoryCrawler
Build ANSSI-FR/ADCP-libdev or download the binary release; copy the required folders in the the `libdev` folder (see the readme.txt file in it).

Build it from a Visual Studio shell:
```console
msbuild DirectoryCrawler.sln /p:Configuration=Debug /p:Platform=Win32
msbuild DirectoryCrawler.sln /p:Configuration=Debug /p:Platform=x64
msbuild DirectoryCrawler.sln /p:Configuration=Release /p:Platform=Win32
msbuild DirectoryCrawler.sln /p:Configuration=Release /p:Platform=x64
```

or directly from Visual Studio.
