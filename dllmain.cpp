#include "pch.h"
#include <memory>
#include <optional>
#include <string>

#pragma warning(push)
#pragma warning(disable : 4267)
#include "externals/REFramework/include/reframework/API.hpp"
#pragma warning(pop)

#define PLUGIN_NAME "REFramework-SpecialK"
#define LOG_INFO(f, ...) reframework::API::get()->log_info(PLUGIN_NAME ": " f, __VA_ARGS__);
#define LOG_INFO0(s) LOG_INFO("%s", s)
#define LOG_ERROR(f, ...) reframework::API::get()->log_error(PLUGIN_NAME ": " f, __VA_ARGS__);
#define LOG_ERROR0(s) LOG_ERROR("%s", s)

namespace {
HMODULE hThisModule;

class RegKeyCloseGuard {
public:
    RegKeyCloseGuard(HKEY hKey): hKey_(hKey) {}
    ~RegKeyCloseGuard() {
        RegCloseKey(hKey_);
    }
    RegKeyCloseGuard(const RegKeyCloseGuard &) = delete;
    RegKeyCloseGuard &operator=(const RegKeyCloseGuard &) = delete;
private:
    HKEY hKey_;
};

std::optional<std::wstring> GetSpecialKPathFromRegistry() {
    HKEY hKey;
    const auto regOpenStatus{ RegOpenKeyEx(
        HKEY_CURRENT_USER, L"Software\\Kaldaien\\Special K",
        0, KEY_QUERY_VALUE, &hKey) };
    if (regOpenStatus != ERROR_SUCCESS) {
        return std::nullopt;
    }
    RegKeyCloseGuard hKeyGuard{ hKey };
    WCHAR buffer[MAX_PATH + 1];
    DWORD szBuffer{ MAX_PATH + 1 };
    const auto regGetValueStatus{ RegGetValue(
        hKey, NULL, L"Path", RRF_RT_REG_SZ, NULL, buffer, &szBuffer
    ) };
    if (regGetValueStatus != ERROR_SUCCESS) {
        return std::nullopt;
    }
    return std::wstring{ buffer };
}

} // anonymous namespace

extern "C" __declspec(dllexport) bool reframework_plugin_initialize(const REFrameworkPluginInitializeParam *param) {
    reframework::API::initialize(param);

    auto &&skRegistryPath{ GetSpecialKPathFromRegistry() };
    if (!skRegistryPath) {
        LOG_ERROR0("GetSpecialKPathFromRegistry failed (perhaps Special K is not properly installed?)");
        return false;
    }

    LOG_INFO0("Attempting to load SpecialK...");
    auto skLoadPath{ *skRegistryPath + L"\\SpecialK64.dll" };
    auto skModule{ LoadLibrary(skLoadPath.c_str()) };
    if (!skModule) {
        LOG_ERROR("%s %s", "Failed to load SpecialK");
        return false;
    }
    LOG_INFO0("Successfully loaded SpecialK");
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
