# Mouri's Internal NT API Collections (MINT)

- [简体中文](自述.md)

Mouri's Internal NT API Collections (MINT) was originally called NativeLib or 
ChuyuWindowsInternalAPI. I have changed the name of this project because the 
original name is too long. This project contains the definitions for the 
Windows Internal UserMode API from ntdll.dll, samlib.dll and winsta.dll. This
project is based on a modified fork of https://github.com/processhacker/phnt,
you can browse our fork from https://github.com/Chuyu-Team/phnt.

## The difference from https://github.com/processhacker/phnt
- Single File.
- No kernel mode definitions.
- Compiling using the `/W4 /WX` option is supported.
- No private definition from the https://github.com/processhacker/phnt.
- Optimized for the Windows SDK.
- "Zw*" API is under the management of Windows SDK version macros.

## How to use
Copy MINT.h to your project and directly include it.

```
// If you wonder to use separate namespace, please define the following macro.
#define MINT_USE_SEPARATE_NAMESPACE

#include "MINT.h"
```

## License
Because https://github.com/processhacker/phnt is distributed under the 
Attribution 4.0 International (CC BY 4.0) license. Also I read the 
https://creativecommons.org/licenses/by/4.0/deed.en and know I only need to 
give appropriate credit, provide a link to the license, and indicate if 
changes were made and no additional restrictions. So I relicensed this project
under The MIT License because I also provide some tools to build this project.

## Chuyu Team
