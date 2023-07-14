#include "pch.h"
#include <array>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <future>
#include <chrono>

using namespace std::chrono_literals;

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

std::filesystem::path getModulePath(const HMODULE module) {
    constexpr auto szBuffer = MAX_PATH + 1;
    auto buffer{ std::array<WCHAR, szBuffer>{} };
    const auto nSize = GetModuleFileNameW(module, buffer.data(), szBuffer);
    if (nSize == 0) [[unlikely]] {
        return {};
    }
    return buffer.data();
}

std::filesystem::path getExeName() {
    const auto path{ getModulePath(NULL) };
    if (path.empty()) [[unlikely]] {
        return {};
    }
    return path.filename();
}

std::optional<std::wstring> GetSpecialKPathFromRegistry() {
    HKEY hKey;
    const auto regOpenStatus = RegOpenKeyEx(
        HKEY_CURRENT_USER, L"Software\\Kaldaien\\Special K",
        0, KEY_QUERY_VALUE, &hKey);
    if (regOpenStatus != ERROR_SUCCESS) {
        return std::nullopt;
    }
    struct RegKeyCloser {
        typedef HKEY pointer;
        void operator()(HKEY hKey) {
            RegCloseKey(hKey);
        }
    };
    const auto hKeyGuard = std::unique_ptr<HKEY, RegKeyCloser>{ hKey };
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
    static auto mutex = std::mutex{};
    const auto lock = std::scoped_lock{ mutex };
    static auto exeName = std::string{};
    static auto logStream = ([]() -> std::ofstream {
        const auto logPath = ([]() -> std::wstring {
            auto exePath = getModulePath(NULL);
            if (exePath.empty()) [[unlikely]] {
                return {};
            }
            exeName = exePath.filename().string();
            return exePath.replace_filename(L"SpecialK-Companion.log").wstring();
        })();
        if (logPath.empty()) [[unlikely]] {
            return {};
        }
        return std::ofstream{ logPath };
    })();
    if (logStream.is_open()) {
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
        const auto exeString = "[" + exeName + "] ";
        logStream << exeString << timeString << message << std::endl;
    }
}

void writeLogMessage(const wchar_t *message) {
    const auto length = static_cast<int>(std::wcslen(message) + 1);
    const auto ansi = std::make_unique<char[]>(length);
    const auto convertedLength = WideCharToMultiByte(
        CP_ACP, 0, message, length, ansi.get(), length, nullptr, nullptr);
    if ((convertedLength == 0) || (ansi[static_cast<std::size_t>(length) - 1] != '\0')) {
        return;
    }
    writeLogMessage(ansi.get());
}

template <class T = wchar_t>
auto getModifiedEnvironmentBlock() {
    auto buffer = ([]() {
        // Populate a vector with the existing environment.
        auto buffer = std::vector<T>{};
        struct Deleter {
            void operator()(T *strings) {
                FreeEnvironmentStrings(strings);
            }
        };
        const auto block = std::unique_ptr<T[], Deleter>{ GetEnvironmentStrings() };
        for (auto i = uint64_t{ 0 }; ; ++i) {
            const auto isNull = (block[i] == '\0');
            if (isNull && (i == 0)) {
                break;
            }
            buffer.emplace_back(block[i]);
            if (isNull && (block[i + 1] == '\0')) {
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

struct ProcessInformationDeleter {
    void operator()(PROCESS_INFORMATION *p) {
        CloseHandle(p->hProcess);
        CloseHandle(p->hThread);
        delete p;
    }
};
typedef std::unique_ptr<PROCESS_INFORMATION, ProcessInformationDeleter> ManagedProcessInformation;

ManagedProcessInformation executeExe(LPCWSTR filename, WCHAR commandLine[]) {
    auto startupInfo = STARTUPINFO{ .cb{ sizeof(STARTUPINFO) } };
    auto processInformation = ManagedProcessInformation{ new PROCESS_INFORMATION{} };

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
            processInformation.get());
    if (!bSuccess) {
        return nullptr;
    }
    return processInformation;
}

bool injectModule(const HMODULE hInjectModule, const HANDLE hProcess) {
    writeLogMessage("Attempting to inject module into process...");
    const auto dllPath = getModulePath(hInjectModule).wstring();
    if (dllPath.empty()) {
        writeLogMessage("Error: Couldn't get path of module");
        return false;
    }
    const auto memoryLength = (dllPath.length() + 1) * sizeof(decltype(dllPath)::value_type);
	const auto dllAddr = VirtualAllocEx(hProcess, nullptr, memoryLength,
        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!dllAddr) {
        writeLogMessage("Error: Failed to allocate memory in target process");
        return false;
    }
    if (!WriteProcessMemory(hProcess, dllAddr, dllPath.c_str(), memoryLength, nullptr)) {
        writeLogMessage("Error: Failed to write to memory of target process");
        return false;
    }
    const auto hThread = CreateRemoteThread(hProcess, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryW),
        reinterpret_cast<LPVOID *>(dllAddr), 0, nullptr);
    if (!hThread) {
        writeLogMessage("Error: Failed to create remote thread");
        return false;
    }
    writeLogMessage("Successfully injected module into target process");
    return true;
}

bool tryLoadSpecialK(const HMODULE hThisModule, bool bUseLoadLibrary = true) {
    constexpr auto lpMutexName{ L"Local\\REFrameworkSpecialKRunOnceMutex" };
    const auto hMutex{ CreateMutex(NULL, TRUE, lpMutexName) };
    if (!hMutex) {
        return true;
    }
    if (WaitForSingleObject(hMutex, 0) != WAIT_OBJECT_0) {
        return true;
    }

    const auto skRegistryPath{ GetSpecialKPathFromRegistry() };
    if (!skRegistryPath) {
        writeLogMessage("GetSpecialKPathFromRegistry failed (perhaps Special K is not properly installed?)");
        return false;
    }

    writeLogMessage((L"Found Special K in " + *skRegistryPath).c_str());
    writeLogMessage("Attempting to load Special K...");

    if (bUseLoadLibrary) {
        const auto skLoadPath{ *skRegistryPath + L"\\SpecialK64.dll" };
        const auto skModule = LoadLibrary(skLoadPath.c_str());
        if (!skModule) {
            writeLogMessage("Failed to load Special K");
            return false;
        }
        writeLogMessage("Successfully loaded Special K");
    } else {
        const auto skLoadPath{ *skRegistryPath + L"\\SKIF.exe" };
        auto commandLine{ std::to_array(L"SKIF.exe Start Temp") };
        const auto process = executeExe(skLoadPath.c_str(), commandLine.data());
        if (process) {
            writeLogMessage("Successfully ran `SKIF Start Temp`");
            if (hThisModule) {
                injectModule(hThisModule, process->hProcess);
            }
        }
    }
    return true;
}

void quitSkif() {
    const auto skRegistryPath{ GetSpecialKPathFromRegistry() };
    if (!skRegistryPath) {
        return;
    }
    const auto skLoadPath{ *skRegistryPath + L"\\SKIF.exe" };
    auto commandLine{ std::to_array(L"SKIF.exe Quit") };
    if (executeExe(skLoadPath.c_str(), commandLine.data())) {
        writeLogMessage("Successfully ran `SKIF Quit`");
    }
}

void onReShadePresent(reshade::api::command_queue *,
        reshade::api::swapchain *, const reshade::api::rect *,
        const reshade::api::rect *, uint32_t, const reshade::api::rect *) {
    reshade::unregister_event<reshade::addon_event::present>(&onReShadePresent);
    CreateThread(NULL, 0, [](LPVOID) -> DWORD {
        Sleep(4 * 1000);
        quitSkif();
        return 0;
    }, NULL, 0, NULL);
}

void onReShadeBeginEffects(reshade::api::effect_runtime *runtime, reshade::api::command_list *,
        reshade::api::resource_view, reshade::api::resource_view) {
    static auto future = std::shared_future<bool>{};
    if (future.valid()) {
        if (future.wait_for(1ms) != std::future_status::ready) {
            // Continue waiting for the thread.
            return;
        }
        // We got a result back from the thread.
        reshade::unregister_event<reshade::addon_event::reshade_begin_effects>(&onReShadeBeginEffects);
        const auto enableEffects = future.get();
        writeLogMessage(enableEffects ? "Enabling ReShade effects" : "Disabling ReShade effects");
        runtime->set_effects_state(enableEffects);
        return;
    }

    // Spawn a thread to figure out which game is running.
    struct ThreadDataHwnd {
        HWND hwnd;
        std::promise<bool> p;
    };
    auto data = new ThreadDataHwnd{ reinterpret_cast<HWND>(runtime->get_hwnd()) };
    future = data->p.get_future().share();

    CreateThread(NULL, 0, [](LPVOID lpData) -> DWORD {
        auto data = std::unique_ptr<ThreadDataHwnd>{ reinterpret_cast<ThreadDataHwnd *>(lpData) };

        while (data->hwnd) {
            constexpr auto szBuffer = 500;
            auto buffer{ std::array<char, szBuffer>{} };
            writeLogMessage("onReShadeBeginEffects: About to call GetWindowTextA");
            const auto szWindowText = GetWindowTextA(data->hwnd, buffer.data(), szBuffer);
            if (szWindowText == 0) {
                writeLogMessage("Failed to obtain the text in the title bar of the window");
                data->p.set_value(false);
                break;
            }
            writeLogMessage("onReShadeBeginEffects: About to create `windowTitle` object");
            const auto windowTitle{ std::string{ buffer.data() } };
            writeLogMessage(("Window title bar: " + windowTitle).c_str());
            if (windowTitle.find("The Legend of Zelda: Tears of the Kingdom") != std::string::npos) {
                data->p.set_value(true);
                break;
            }
            data->hwnd = GetAncestor(data->hwnd, GA_PARENT);
            writeLogMessage(static_cast<std::ostringstream &&>((
                std::ostringstream{} << "Parent hwnd: " << data->hwnd)).str().c_str());
        }
        return 0;
    }, data, 0, NULL);
}

void onReShadeCreateEffectRuntime(reshade::api::effect_runtime *runtime) {
    if (!bUsingReShadeYuzu) {
        return;
    }
    reshade::register_event<reshade::addon_event::reshade_begin_effects>(&onReShadeBeginEffects);
}

struct HandleCloser {
    typedef HANDLE pointer;
    void operator()(HANDLE handle) {
        CloseHandle(handle);
    }
};
typedef std::unique_ptr<HANDLE, HandleCloser> ManagedHandle;

DWORD getParentPid() {
    const auto snapshot = ([]() -> ManagedHandle {
        const auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return nullptr;
        }
        return ManagedHandle{ hSnapshot };
    })();
    if (!snapshot) {
        writeLogMessage("Error: CreateToolhelp32Snapshot failed");
        return 0;
    }
    auto entry = PROCESSENTRY32{ .dwSize{ sizeof(PROCESSENTRY32) } };
    auto success = Process32First(snapshot.get(), &entry);
    const auto pid = GetCurrentProcessId();
    while (true) {
        if (!success) {
            writeLogMessage("Error: Process32First failed");
            if (GetLastError() == ERROR_NO_MORE_FILES) {
                writeLogMessage("(ERROR_NO_MORE_FILES)");
            }
            return 0;
        }
        if (entry.th32ProcessID == pid) {
            writeLogMessage("Found this process in the snapshot");
            return entry.th32ParentProcessID;
        }
        success = Process32Next(snapshot.get(), &entry);
    }
}

void runSkifLogic() {
    writeLogMessage("Detected DLL loaded into SKIF process");
    const auto parentPid = getParentPid();
    writeLogMessage(static_cast<std::ostringstream &&>((
        std::ostringstream{} << "Parent PID: " << parentPid)).str().c_str());
    if (parentPid == 0) {
        return;
    }
    auto parent = ManagedHandle{ OpenProcess(SYNCHRONIZE, false, parentPid) };
    if (!parent) {
        writeLogMessage("Failed to open parent process");
        return;
    }
    writeLogMessage("Waiting indefinitely for parent process to close...");
    if (WaitForSingleObject(parent.get(), INFINITE) == WAIT_FAILED) {
        writeLogMessage("Failed to wait for parent process");
        return;
    }
    writeLogMessage("Detected that parent process has closed");
    quitSkif();
}

void doProcessAttach(HMODULE hModule) {
    DisableThreadLibraryCalls(hModule);
    struct ThreadData {
        HMODULE hModule;
    };
    auto data = new ThreadData{ hModule };
    CreateThread(NULL, 0, [](LPVOID lpData) -> DWORD {
        const auto data = std::unique_ptr<ThreadData>{ reinterpret_cast<ThreadData *>(lpData) };
        const auto path{ getModulePath(data->hModule) };
        if (path.empty()) [[unlikely]] {
            return 0;
        }
        const auto dllName{ path.filename() };
        if (dllName == L"dxgi.dll") {
            if (getExeName() != L"SKIF.exe") {
                tryLoadSpecialK(data->hModule, false);
            } else {
                runSkifLogic();
            }
        }
        return 0;
    }, data, 0, NULL);
}

} // anonymous namespace

extern "C" __declspec(dllexport) bool reframework_plugin_initialize(
        const REFrameworkPluginInitializeParam *param) {
    bUsingREFramework = true;
    reframework::API::initialize(param);
    return tryLoadSpecialK(NULL);
}

extern "C" __declspec(dllexport) bool AddonInit(HMODULE addon_module, HMODULE /*reshade_module*/) {
    if (!reshade::register_addon(addon_module)) {
        return false;
    }
    bUsingReShade = true;
    reshade::register_event<reshade::addon_event::present>(&onReShadePresent);
    reshade::register_event<reshade::addon_event::init_effect_runtime>(&onReShadeCreateEffectRuntime);
    writeLogMessage("Add-on successfully registered");

    if (getExeName() == L"yuzu.exe") {
        bUsingReShadeYuzu = true;
        writeLogMessage("Detected running of Yuzu with ReShade");
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
