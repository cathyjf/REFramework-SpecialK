#include "pch.h"
#include <array>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
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
auto bUsingReShadeYuzu = false;
auto bEnableReShadeYuzuEffects = false;

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
        const auto finalMessage{ std::string{ "SpecialK Companion: " } + message };
        reshade::log_message(reshade::log_level::info, finalMessage.c_str());
    }
    static std::mutex mutex;
    std::scoped_lock lock{ mutex };
    static auto logStream = ([]() -> std::optional<std::ofstream> {
        const auto logPath = ([]() -> std::optional<std::wstring> {
            const auto szBuffer = MAX_PATH + 1;
            auto buffer{ std::array<WCHAR, szBuffer>{} };
            const auto nSize = GetModuleFileName(NULL, buffer.data(), szBuffer);
            if (nSize == 0) [[unlikely]] {
                return std::nullopt;
            }
            return std::filesystem::path{ buffer.data() }
                .replace_filename(L"SpecialK-Companion.log")
                .wstring();
        })();
        if (!logPath) [[unlikely]] {
            return std::nullopt;
        }
        return std::ofstream{ *logPath };
    })();
    if (logStream) {
        const auto timeString = ([]() -> std::string {
            const auto time = std::time(nullptr);
            if (time == -1) [[unlikely]] {
                return "[time failed] ";
            }
            auto localtime = tm{};
            if (localtime_s(&localtime, &time) != ERROR_SUCCESS) [[unlikely]] {
                return "[localtime_s failed] ";
            }
            auto buffer{ std::array<char, std::size("yyyy-mm-dd hh:mm:ss")>{} };
            const auto length = std::strftime(buffer.data(), buffer.size(), "%F %T", &localtime);
            if (length == 0) [[unlikely]] {
                return "[strftime failed] ";
            }
            return "[" + std::string{ buffer.data() } + "] ";
        })();
        *logStream << timeString << message << std::endl;
    }
}

template <class T = wchar_t>
std::vector<T> getModifiedEnvironmentBlock() {
    auto buffer = ([]() {
        // Populate a vector with the existing environment.
        auto buffer = std::vector<T>{};
        struct Deleter {
            void operator()(T* strings) {
                FreeEnvironmentStrings(strings);
            }
        };
        const auto block = std::unique_ptr<T[], Deleter>{ GetEnvironmentStrings() };
        for (auto i = 0; ; ++i) {
            buffer.emplace_back(block[i]);
            if (block[i] != '\0') {
                continue;
            }
            if ((i == '\0') || (block[i + 1] == '\0')) {
                break;
            }
        }
        return buffer;
    })();
    // Add our new environment variable to the buffer.
    constexpr T newEnv[] = L"SteamNoOverlayUIDrawing=1";
    constexpr auto newEnvLength = sizeof(newEnv) / sizeof(newEnv[0]);
    buffer.insert(buffer.end(), newEnv, newEnv + newEnvLength);
    // The environment block requires a final null terminator.
    buffer.emplace_back('\0');
    return buffer;
}

bool executeExe(LPCWSTR filename, WCHAR commandLine[], bool waitForExe = false, bool addToJob = false) {
    auto startupInfo{ STARTUPINFO{ .cb{ sizeof(STARTUPINFO) } } };
    auto processInformation{ PROCESS_INFORMATION{} };

    // Note: The string used to hold the command line cannot be const because
    // the CreateProcess function reserves the right to modify the string.
    auto environment = getModifiedEnvironmentBlock();
    const auto bSuccess = CreateProcess(
            filename,
            commandLine,
            NULL,  // lpProcessAttributes
            NULL,  // lpThreadAttributes
            FALSE, // bInheritHandles
            CREATE_UNICODE_ENVIRONMENT, // dwCreationFlags
            &environment[0],            // lpEnvironment
            NULL,  // lpCurrentDirectory
            &startupInfo,
            &processInformation);
    if (!bSuccess) {
        return false;
    }

    if (waitForExe) {
        WaitForSingleObject(processInformation.hProcess, INFINITE);
    }

    if (addToJob) {
#if 0 == 1
        // This code does not work correctly yet.
        writeLogMessage("Attempting to create job object...");
        auto hJob = CreateJobObject(nullptr, nullptr);
        if (hJob) {
            writeLogMessage("Successfully created job object");
            auto limitInfo = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
                JOBOBJECT_BASIC_LIMIT_INFORMATION { .LimitFlags {
                    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                } }
            };
            auto bSetJobInformation = SetInformationJobObject(
                hJob, JobObjectExtendedLimitInformation, &limitInfo, sizeof(limitInfo));
            if (!bSetJobInformation) {
                writeLogMessage("Failed to set job information");
                CloseHandle(hJob);
            } else {
                writeLogMessage("Successfully set job information");
                auto bAssignProcess = AssignProcessToJobObject(hJob, processInformation.hProcess);
                if (!bAssignProcess) {
                    writeLogMessage("Failed to assign child process to job");
                    CloseHandle(hJob);
                } else {
                    // The handle `hJob` is intentionally not closed at this point.
                    // It will be closed implicitly when this process terminates.
                    writeLogMessage("Assigned child process to job");
                }
            }
        }
#endif
    }

    CloseHandle(processInformation.hProcess);
    CloseHandle(processInformation.hThread);
    return true;
}

bool tryLoadSpecialK(bool bUseLoadLibrary = true) {
    constexpr auto lpMutexName{ L"Local\\REFrameworkSpecialKRunOnceMutex" };
    const auto &&hMutex{ CreateMutex(NULL, TRUE, lpMutexName) };
    if (!hMutex) {
        return true;
    }
    if (WaitForSingleObject(hMutex, 0) != WAIT_OBJECT_0) {
        return true;
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
        if (executeExe(skLoadPath.c_str(), commandLine.data(), false, true)) {
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

void onReShadePresent(reshade::api::command_queue *,
        reshade::api::swapchain *, const reshade::api::rect *,
        const reshade::api::rect *, uint32_t, const reshade::api::rect *) {
    reshade::unregister_event<reshade::addon_event::present>(&onReShadePresent);
    spawnSKIFQuitThread();
}

void onReShadeBeginEffects(reshade::api::effect_runtime *runtime, reshade::api::command_list *,
        reshade::api::resource_view, reshade::api::resource_view) {
    reshade::unregister_event<reshade::addon_event::reshade_begin_effects>(&onReShadeBeginEffects);
    if (bEnableReShadeYuzuEffects) {
        return;
    }
    auto hwnd = reinterpret_cast<HWND>(runtime->get_hwnd());
    while (hwnd) {
        const auto szBuffer = 500;
        auto buffer{ std::array<char, szBuffer>{} };
        const auto szWindowText = GetWindowTextA(hwnd, buffer.data(), szBuffer);
        if (szWindowText == 0) {
            writeLogMessage("Failed to obtain the text in the title bar of the window");
            break;
        }
        const auto windowTitle{ std::string{ buffer.data() } };
        writeLogMessage(("Window title bar: " + windowTitle).c_str());
        if (windowTitle.find("The Legend of Zelda: Tears of the Kingdom") != std::string::npos) {
            bEnableReShadeYuzuEffects = true;
            break;
        }
        hwnd = GetAncestor(hwnd, GA_PARENT);
        writeLogMessage(static_cast<std::ostringstream &&>((
            std::ostringstream{} << "Parent hwnd: " << hwnd)).str().c_str());
    }
    writeLogMessage(bEnableReShadeYuzuEffects ? "Enabling ReShade effects" : "Disabling ReShade effects");
    runtime->set_effects_state(bEnableReShadeYuzuEffects);
}

void onReShadeCreateEffectRuntime(reshade::api::effect_runtime *runtime) {
    if (!bUsingReShadeYuzu) {
        return;
    }
    reshade::register_event<reshade::addon_event::reshade_begin_effects>(&onReShadeBeginEffects);
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
    reshade::register_event<reshade::addon_event::init_effect_runtime>(&onReShadeCreateEffectRuntime);
    writeLogMessage("Add-on successfully registered");

    const auto szBuffer = MAX_PATH + 1;
    auto buffer{ std::array<WCHAR, szBuffer>{} };
    const auto nSize = GetModuleFileName(NULL, buffer.data(), szBuffer);
    if (nSize != 0) {
        const auto exeName{ std::filesystem::path{ buffer.data() }.filename() };
        if (exeName == L"yuzu.exe") {
            bUsingReShadeYuzu = true;
            writeLogMessage("Detected running of Yuzu with ReShade");
        }
    }

    return true;
}

extern "C" __declspec(dllexport) void AddonUninit(HMODULE addon_module, HMODULE /*reshade_module*/) {
    if (!bUsingReShade) {
        return;
    }
    reshade::unregister_event<reshade::addon_event::present>(&onReShadePresent);
    reshade::unregister_event<reshade::addon_event::init_effect_runtime>(&onReShadeCreateEffectRuntime);
    reshade::unregister_event<reshade::addon_event::reshade_begin_effects>(&onReShadeBeginEffects);
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
