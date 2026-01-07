# FreeimageCrash
crash samples by fuzz

# Use-After-Free Vulnerability in FreeImage (PluginTARGA)

**Author**: [MiracleWolf]
**Date**: 2026-01-07
**Vendor**: FreeImage Project
**Product**: FreeImage
**Version**: 3.18.0 (Latest)
**Vulnerability Type**: Use-After-Free
**Platform**: Windows

## 1. Summary
A Use-After-Free (UAF) vulnerability was discovered in the FreeImage library (version 3.18.0). The vulnerability exists in the TGA image loader (`PluginTARGA.cpp`). When loading a crafted TGA image with RLE compression enabled, if the internal `loadRLE` function fails, it frees the image memory. However, the calling function (`Load`) retains a dangling pointer to the freed memory and subsequently uses it during image flipping operations, leading to a crash (Denial of Service) or potential arbitrary code execution.

## 2. Root Cause Analysis
The vulnerability is caused by a "pass-by-value" pointer issue in the helper function `loadRLE`.

**File**: `Source/FreeImage/PluginTARGA.cpp`

1.  **Improper Pointer Management**:
    The `loadRLE` function accepts the bitmap pointer `FIBITMAP* dib` by value:
    ```cpp
    // PluginTARGA.cpp, line ~520+
    static void loadRLE(FIBITMAP* dib, ...) { ... }
    ```
2.  **Premature Free**:
    When `loadRLE` encounters an error (e.g., malformed RLE data or IO error), it releases the memory:
    ```cpp
    // PluginTARGA.cpp, line ~543+
    if (cache.isNull()) {
        FreeImage_Unload(dib); // Memory is freed here
        dib = NULL;            // Local copy is set to NULL, but caller's pointer remains unchanged
        return;
    }
    ```
3.  **Use-After-Free**:
    The calling function `Load` continues execution with the now-dangling `dib` pointer. If the TGA header specifies a vertical or horizontal flip (via the Image Descriptor byte), the code attempts to access the freed memory:
    ```cpp
    // PluginTARGA.cpp, line ~1060+
    if (flipvert) {
        FreeImage_FlipVertical(dib); // CRASH: Uses dangling pointer
    }
    if (fliphoriz) {
        FreeImage_FlipHorizontal(dib); // CRASH: Uses dangling pointer
    }
    ```

## 3. Proof of Concept (PoC)

### Reproduction Environment
* **OS**: Windows 11 x64
* **Compiler**: MSVC (Visual Studio 2019)
* **Library Build**: FreeImage 3.18.0 (Debug&Release)

### Crash Evidence
When compiled with Debug flags, the application crashes with an Access Violation reading specific debug fill patterns 

Windbg result:
0:000> g
ModLoad: 10000000 107df000   C:\Users\Administrator\source\repos\Freeimage_test\Release\FreeImaged.dll
ModLoad: 764f0000 76551000   C:\WINDOWS\SysWOW64\WS2_32.dll
ModLoad: 758e0000 7599c000   C:\WINDOWS\SysWOW64\RPCRT4.dll
(2714.3218): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** WARNING: Unable to verify checksum for C:\Users\Administrator\source\repos\Freeimage_test\Release\FreeImaged.dll
eax=06700ff8 ebx=058f0f70 ecx=00000000 edx=00030000 esi=0019f30c edi=0019f300
eip=1000caf5 esp=0019f104 ebp=0019f1d4 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010202
FreeImaged!FreeImage_HasPixels+0x15:
1000caf5 8b08            mov     ecx,dword ptr [eax]  ds:002b:06700ff8=????????
0:000> !analyze -v
Reloading current modules
..*** WARNING: Unable to verify checksum for C:\Users\Administrator\source\repos\Freeimage_test\Release\FreeImaged.dll
.........
*******************************************************************************
*                                                                             *
*                        Exception Analysis                                   *
*                                                                             *
*******************************************************************************

*** WARNING: Unable to verify checksum for Freeimage_test.exe

KEY_VALUES_STRING: 1

    Key  : AV.Type
    Value: Read

    Key  : Analysis.CPU.mSec
    Value: 1109

    Key  : Analysis.Elapsed.mSec
    Value: 6063

    Key  : Analysis.IO.Other.Mb
    Value: 0

    Key  : Analysis.IO.Read.Mb
    Value: 23

    Key  : Analysis.IO.Write.Mb
    Value: 21

    Key  : Analysis.Init.CPU.mSec
    Value: 468

    Key  : Analysis.Init.Elapsed.mSec
    Value: 39398

    Key  : Analysis.Memory.CommitPeak.Mb
    Value: 65

    Key  : Analysis.Version.DbgEng
    Value: 10.0.29482.1003

    Key  : Analysis.Version.Description
    Value: 10.2509.29.03 x86fre

    Key  : Analysis.Version.Ext
    Value: 1.2509.29.3

    Key  : Failure.Bucket
    Value: INVALID_POINTER_READ_AVRF_c0000005_FreeImaged.dll!FreeImage_HasPixels

    Key  : Failure.Exception.Code
    Value: 0xc0000005

    Key  : Failure.Exception.IP.Address
    Value: 0x1000caf5

    Key  : Failure.Exception.IP.Module
    Value: FreeImaged

    Key  : Failure.Exception.IP.Offset
    Value: 0xcaf5

    Key  : Failure.Hash
    Value: {259a0c43-5140-5e12-e7c1-08b76d9f11b2}

    Key  : Failure.ProblemClass.Primary
    Value: INVALID_POINTER_READ

    Key  : Faulting.IP.Type
    Value: Paged

    Key  : Timeline.OS.Boot.DeltaSec
    Value: 523584

    Key  : Timeline.Process.Start.DeltaSec
    Value: 39

    Key  : WER.OS.Branch
    Value: ge_release

    Key  : WER.OS.Version
    Value: 10.0.26100.1


NTGLOBALFLAG:  2000000

APPLICATION_VERIFIER_FLAGS:  0

APPLICATION_VERIFIER_LOADED: 1

EXCEPTION_RECORD:  (.exr -1)
ExceptionAddress: 1000caf5 (FreeImaged!FreeImage_HasPixels+0x00000015)
   ExceptionCode: c0000005 (Access violation)
  ExceptionFlags: 00000000
NumberParameters: 2
   Parameter[0]: 00000000
   Parameter[1]: 06700ff8
Attempt to read from address 06700ff8

FAULTING_THREAD:  3218

PROCESS_NAME:  Freeimage_test.exe

READ_ADDRESS:  06700ff8 

ERROR_CODE: (NTSTATUS) 0xc0000005 - 0x%p            0x%p                    %s

EXCEPTION_CODE_STR:  c0000005

EXCEPTION_PARAMETER1:  00000000

EXCEPTION_PARAMETER2:  06700ff8

STACK_TEXT:  
0019f1d4 100aa414     06700ff8 0019fcd4 0019f30c FreeImaged!FreeImage_HasPixels+0x15
0019f300 10050c91     06700ff8 ec33d474 0019fdf0 FreeImaged!FreeImage_FlipVertical+0x24
0019fce4 10019bb8     0019fef0 066f0fc0 ffffffff FreeImaged!Load+0x1121
0019fdf0 10019c56     00000011 0019fef0 066f0fc0 FreeImaged!FreeImage_LoadFromHandle+0x88
0019ff04 00401223     00000011 058f0f70 00000000 FreeImaged!FreeImage_LoadU+0x56
(Inline) --------     -------- -------- -------- Freeimage_test!FreeImage_test+0x13
0019ff2c 00401865     00000002 058ecf58 057a9ef0 Freeimage_test!main+0x1d3
(Inline) --------     -------- -------- -------- Freeimage_test!invoke_main+0x1c
0019ff74 76405d49     0024e000 76405d30 0019ffdc Freeimage_test!__scrt_common_main_seh+0xfa
0019ff84 77cbd5db     0024e000 071251de 00000000 KERNEL32!BaseThreadInitThunk+0x19
0019ffdc 77cbd561     ffffffff 77d044c7 00000000 ntdll!__RtlUserThreadStart+0x2b
0019ffec 00000000     004018ed 0024e000 00000000 ntdll!_RtlUserThreadStart+0x1b


STACK_COMMAND: ~0s; .ecxr ; kb

IP_IN_PAGED_CODE: 
FreeImaged!FreeImage_HasPixels+15 [D:\FreeImage\Source\FreeImage\BitmapAccess.cpp @ 820]
1000caf5 8b08            mov     ecx,dword ptr [eax]

FAULTING_SOURCE_LINE:  D:\FreeImage\Source\FreeImage\BitmapAccess.cpp

FAULTING_SOURCE_FILE:  D:\FreeImage\Source\FreeImage\BitmapAccess.cpp

FAULTING_SOURCE_LINE_NUMBER:  820

FAULTING_SOURCE_CODE:  
   816: // ----------------------------------------------------------
   817: 
   818: BOOL DLL_CALLCONV 
   819: FreeImage_HasPixels(FIBITMAP *dib) {
>  820: 	return (dib != NULL) ? ((FREEIMAGEHEADER *)dib->data)->has_pixels : FALSE;
   821: }
   822: 
   823: // ----------------------------------------------------------
   824: 
   825: BOOL DLL_CALLCONV


SYMBOL_NAME:  FreeImaged!FreeImage_HasPixels+15

MODULE_NAME: FreeImaged

IMAGE_NAME:  FreeImaged.dll

FAILURE_BUCKET_ID:  INVALID_POINTER_READ_AVRF_c0000005_FreeImaged.dll!FreeImage_HasPixels

OS_VERSION:  10.0.26100.1

BUILDLAB_STR:  ge_release

OSPLATFORM_TYPE:  x86

OSNAME:  Windows 10

IMAGE_VERSION:  3.18.0.0

FAILURE_ID_HASH:  {259a0c43-5140-5e12-e7c1-08b76d9f11b2}

Followup:     MachineOwner
---------

0:000> !heap -p -a 06724ff8
    address 06724ff8 found in
    _DPH_HEAP_ROOT @ 3d71000
    in free-ed allocation (  DPH_HEAP_BLOCK:         VirtAddr         VirtSize)
                                    65c29c0:          6724000             2000
    7924b162 verifier!AVrfDebugPageHeapFree+0x000000c2
    77d44f09 ntdll!RtlDebugFreeHeap+0x0000003e
    77c9fda6 ntdll!RtlpFreeHeap+0x000000d6
    77ce2092 ntdll!RtlpFreeNTHeapInternal+0x000006b5
    77c8ecaa ntdll!RtlFreeHeap+0x000000ca
    104738d7 FreeImaged!_free_base+0x00000027 [minkernel\crts\ucrt\src\appcrt\heap\free_base.cpp @ 105]
    1044d1b6 FreeImaged!free_dbg_nolock+0x000004f6 [minkernel\crts\ucrt\src\appcrt\heap\debug_heap.cpp @ 1001]
    1044bc6c FreeImaged!_free_dbg+0x0000007c [minkernel\crts\ucrt\src\appcrt\heap\debug_heap.cpp @ 1030]
    104285ce FreeImaged!operator delete+0x0000000e [D:\a\_work\1\s\src\vctools\crt\vcstartup\src\heap\delete_scalar.cpp @ 34]
    104264bc FreeImaged!operator delete+0x0000000c [D:\a\_work\1\s\src\vctools\crt\vcstartup\src\heap\delete_scalar_size.cpp @ 31]
    10006f2b +0x0000003b
    1000d82c FreeImaged!FreeImage_Unload+0x000001bc [D:\FreeImage\Source\FreeImage\BitmapAccess.cpp @ 520]
    1004ed9d FreeImaged!loadRLE<16>+0x0000010d [D:\FreeImage\Source\FreeImage\PluginTARGA.cpp @ 597]
    10050937 FreeImaged!Load+0x00000dc7 [D:\FreeImage\Source\FreeImage\PluginTARGA.cpp @ 960]
    10019bb8 FreeImaged!FreeImage_LoadFromHandle+0x00000088 [D:\FreeImage\Source\FreeImage\Plugin.cpp @ 388]
    10019c56 FreeImaged!FreeImage_LoadU+0x00000056 [D:\FreeImage\Source\FreeImage\Plugin.cpp @ 428]
    00401223 Freeimage_test!main+0x000001d3 [C:\Users\Administrator\source\repos\Freeimage_test\main.cpp @ 142]
    00401865 Freeimage_test!__scrt_common_main_seh+0x000000fa [D:\a\_work\1\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl @ 288]
    76405d49 KERNEL32!BaseThreadInitThunk+0x00000019
    77cbd5db ntdll!__RtlUserThreadStart+0x0000002b
    77cbd561 ntdll!_RtlUserThreadStart+0x0000001b

