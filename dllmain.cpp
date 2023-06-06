#include "pch.h"
#include <array>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>

#pragma warning(push)
#pragma warning(disable : 4267 26110)
#include "externals/REFramework/include/reframework/API.hpp"
#pragma warning(pop)

#pragma warning(push)
#pragma warning(disable : 26827)
#include "externals/reshade/include/reshade.hpp"
#pragma warning(pop)

#include "dxgi.proxydll.h"

namespace {
auto bUsingREFramework = false;
auto bUsingReShade = false;

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
    const auto regOpenStatus = RegOpenKeyEx(
        HKEY_CURRENT_USER, L"Software\\Kaldaien\\Special K",
        0, KEY_QUERY_VALUE, &hKey);
    if (regOpenStatus != ERROR_SUCCESS) {
        return std::nullopt;
    }
    const auto hKeyGuard{ RegKeyCloseGuard{ hKey } };
    auto buffer{ std::array<WCHAR, MAX_PATH + 1>{} };
    auto szBuffer = DWORD{ MAX_PATH + 1 };
    const auto regGetValueStatus = RegGetValue(
        hKey, NULL, L"Path", RRF_RT_REG_SZ, NULL, buffer.data(), &szBuffer
    );
    if (regGetValueStatus != ERROR_SUCCESS) {
        return std::nullopt;
    }
    return std::wstring{ buffer.data() };
}

void writeLogMessage(const char *message) {
    if (bUsingREFramework) {
        reframework::API::get()->log_info("REFramework-SpecialK: %s", message);
    }
    if (bUsingReShade) {
        reshade::log_message(reshade::log_level::info, message);
    }
}

bool executeExe(LPCWSTR filename, WCHAR commandLine[], bool waitForExe = false) {
    auto startupInfo{ STARTUPINFO{ .cb{ sizeof(STARTUPINFO) } } };
    auto processInformation{ PROCESS_INFORMATION{} };

    // Note: The string used to hold the command line cannot be const because
    // the CreateProcess function reserves the right to modify the string.
    const auto bSuccess = CreateProcess(
            filename,
            commandLine,
            NULL,  // lpProcessAttributes
            NULL,  // lpThreadAttributes
            FALSE, // bInheritHandles
            0,     // dwCreationFlags
            NULL,  // lpEnvironment
            NULL,  // lpCurrentDirectory
            &startupInfo,
            &processInformation);
    if (!bSuccess) {
        return false;
    }

    if (waitForExe) {
        WaitForSingleObject(processInformation.hProcess, INFINITE);
    }
    CloseHandle(processInformation.hProcess);
    CloseHandle(processInformation.hThread);
    return true;
}

bool tryLoadSpecialK(bool bUseLoadLibrary = true) {
    constexpr auto lpMutexName{ L"Local\\REFrameworkSpecialKRunOnceMutex" };
    const auto &&hMutex{ CreateMutex(NULL, TRUE, lpMutexName) };
    if (!hMutex) {
        return 1;
    }
    if (WaitForSingleObject(hMutex, 0) != WAIT_OBJECT_0) {
        return 1;
    }

    static auto bLoadedSpecialK = false;
    static auto bTriedLoadingSpecialK = false;
    if (bTriedLoadingSpecialK) {
        writeLogMessage("Ignored second attempt to load SpecialK");
        return bLoadedSpecialK;
    }
    bTriedLoadingSpecialK = true;

    const auto &&skRegistryPath{ GetSpecialKPathFromRegistry() };
    if (!skRegistryPath) {
        writeLogMessage("GetSpecialKPathFromRegistry failed (perhaps Special K is not properly installed?)");
        return false;
    }

    writeLogMessage("Attempting to load SpecialK...");

    if (bUseLoadLibrary) {
        const auto skLoadPath{ *skRegistryPath + L"\\SpecialK64.dll" };
        const auto skModule = LoadLibrary(skLoadPath.c_str());
        if (!skModule) {
            writeLogMessage("Failed to load SpecialK");
            return false;
        }
        writeLogMessage("Successfully loaded SpecialK");
    } else {
        const auto skLoadPath{ *skRegistryPath + L"\\SKIF.exe" };
        auto commandLine{ std::to_array(L"SKIF.exe Start Temp") };
        if (executeExe(skLoadPath.c_str(), commandLine.data())) {
            writeLogMessage("Successfully ran `SKIF Start Temp`");
        }
    }
    bLoadedSpecialK = true;
    return true;
}

void spawnSKIFQuitThread() {
    CreateThread(NULL, 0, [](LPVOID) -> DWORD {
        Sleep(4 * 1000);
        const auto &&skRegistryPath{ GetSpecialKPathFromRegistry() };
        if (skRegistryPath) {
            const auto skLoadPath{ *skRegistryPath + L"\\SKIF.exe" };
            auto commandLine{ std::to_array(L"SKIF.exe Quit") };
            if (executeExe(skLoadPath.c_str(), commandLine.data())) {
                writeLogMessage("Successfully ran `SKIF Quit`");
            }
        }
        return 0;
    }, NULL, 0, NULL);
}

void spawnSKIFThread(bool bExecuteSkifQuit = true) {
    CreateThread(NULL, 0, [](LPVOID) -> DWORD {
        tryLoadSpecialK(false);
        return 0;
    }, NULL, 0, NULL);
}

void unregisterReShadeEvent();

void onReShadePresent(reshade::api::command_queue *, reshade::api::swapchain *, const reshade::api::rect *,
        const reshade::api::rect *, uint32_t, const reshade::api::rect *) {
    unregisterReShadeEvent();
    spawnSKIFQuitThread();
}

void unregisterReShadeEvent() {
    reshade::unregister_event<reshade::addon_event::present>(&onReShadePresent);
}

void doProcessAttach(HMODULE hModule) {
    DisableThreadLibraryCalls(hModule);
    const auto szBuffer = MAX_PATH + 1;
    auto buffer{ std::array<WCHAR, szBuffer>{} };
    const auto nSize = GetModuleFileName(hModule, buffer.data(), szBuffer);
    if (nSize == 0) {
        return;
    }
    const auto dllName{ std::filesystem::path{ buffer.data() }.filename() };
    if (dllName == L"dxgi.dll") {
        spawnSKIFThread(false);
    }
}

} // anonymous namespace

extern "C" __declspec(dllexport) bool reframework_plugin_initialize(
        const REFrameworkPluginInitializeParam *param) {
    bUsingREFramework = true;
    reframework::API::initialize(param);
    return tryLoadSpecialK();
}

extern "C" __declspec(dllexport) bool AddonInit(HMODULE addon_module, HMODULE /*reshade_module*/) {
    if (!reshade::register_addon(addon_module)) {
        return false;
    }
    bUsingReShade = true;
    reshade::register_event<reshade::addon_event::present>(&onReShadePresent);
    writeLogMessage("Add-on successfully registered");
    return true;
}

extern "C" __declspec(dllexport) void AddonUninit(HMODULE addon_module, HMODULE /*reshade_module*/) {
    if (!bUsingReShade) {
        return;
    }
    unregisterReShadeEvent();
    reshade::unregister_addon(addon_module);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID /*lpReserved*/) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        doProcessAttach(hModule);
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
