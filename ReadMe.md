# Mouri's Internal NT API Collections (MINT)

- [简体中文](自述.md)

Mouri's Internal NT API Collections (MINT) was originally called NativeLib or 
ChuyuWindowsInternalAPI. I have changed the name of this project because the 
original name is too long. This project contains the definitions for the 
Windows Internal UserMode API from ntdll.dll, samlib.dll and winsta.dll. This
project is based on PHNT from [System Informer (originally Process Hacker)].

## The difference from PHNT from [System Informer (originally Process Hacker)]

- Compiling using the `/W4 /WX` option is supported.
- Optimized for the Windows SDK.
- "Zw*" API is under the management of Windows SDK version macros.

## How to use

Copy "Mint" folder to your project, set the include path for that folder and
include Mint.h.

```
// If you wonder to use separate namespace, please define the following macro.
#define MINT_USE_SEPARATE_NAMESPACE

#include "Mint.h"
```

## License

The Mouri's Internal NT API Collections (MINT) is distributed under the MIT
License. Because the [System Informer (originally Process Hacker)] is
distributed under the MIT License now and I'm glad to follow that.

[System Informer (originally Process Hacker)]: https://github.com/winsiderss/systeminformer

## Chuyu Team
