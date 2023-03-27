#include "pch.h"
#include <memory>
#include <optional>
#include <string>

#pragma warning(push)
#pragma warning(disable : 4267)
#include "externals/REFramework/include/reframework/API.hpp"
#pragma warning(pop)

#define PLUGIN_NAME "REFramework-SpecialK"
#define LOG_ERROR(f, ...) reframework::API::get()->log_error(PLUGIN_NAME ": " f, __VA_ARGS__);
#define LOG_ERROR0(s) LOG_ERROR("%s", s)

namespace {
HMODULE hThisModule;

std::optional<std::wstring> GetModulePath(HMODULE hModule) {
    WCHAR wcModuleFilename[MAX_PATH + 1];
    const DWORD szModuleFilename = GetModuleFileName(
            hModule, wcModuleFilename, MAX_PATH);
    if (szModuleFilename == 0) {
        return std::nullopt;
    }
    const std::wstring moduleFilename{ wcModuleFilename };
    const size_t lastSlash = moduleFilename.find_last_of(L'\\');
    return { std::wstring { moduleFilename.substr(0, lastSlash + 1) } };
}

} // anonymous namespace

extern "C" __declspec(dllexport) bool reframework_plugin_initialize(const REFrameworkPluginInitializeParam *param) {
    reframework::API::initialize(param);

   auto &&modulePath{ GetModulePath(hThisModule) };
    if (!modulePath) {
        LOG_ERROR0("GetModulePath failed");
        return false;
    }

    auto skLoadPath{ *modulePath + L"SpecialK\\SpecialK64.dll" };
    auto skModule{ LoadLibrary(skLoadPath.c_str()) };
    if (!skModule) {
        const auto skPathLength{ skLoadPath.length() + 1 };
        auto narrowPathBuffer{ std::make_unique<char>(skPathLength) };
        if (!WideCharToMultiByte(
            CP_ACP,                 // CodePage
            0,                      // dwFlags
            skLoadPath.c_str(),     // lpWideCharStr
            skPathLength,           // cchWideChar
            narrowPathBuffer.get(), // lpMultiByteStr
            skPathLength,           // cbMultiByte
            NULL,                   // lpDefaultChar
            NULL                    // lpUsedDefaultChar
        )) {
            strcpy_s(narrowPathBuffer.get(), skPathLength, "unknown path");
        }
        LOG_ERROR("%s %s", "Failed to load SpecialK from", narrowPathBuffer.get());
        return false;
    }
    return true;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID /*lpReserved*/) {
    hThisModule = hModule;

    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
