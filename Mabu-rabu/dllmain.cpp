// dllmain.cpp : Определяет точку входа для приложения DLL.
#include "pch.h"
// Проброс всех 17 экспортов оригинальной version.dll (x64)
#pragma comment(linker, "/export:GetFileVersionInfoA=C:\\Windows\\System32\\version.GetFileVersionInfoA")
#pragma comment(linker, "/export:GetFileVersionInfoByHandle=C:\\Windows\\System32\\version.GetFileVersionInfoByHandle")
#pragma comment(linker, "/export:GetFileVersionInfoExA=C:\\Windows\\System32\\version.GetFileVersionInfoExA")
#pragma comment(linker, "/export:GetFileVersionInfoExW=C:\\Windows\\System32\\version.GetFileVersionInfoExW")
#pragma comment(linker, "/export:GetFileVersionInfoSizeA=C:\\Windows\\System32\\version.GetFileVersionInfoSizeA")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExA=C:\\Windows\\System32\\version.GetFileVersionInfoSizeExA")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExW=C:\\Windows\\System32\\version.GetFileVersionInfoSizeExW")
#pragma comment(linker, "/export:GetFileVersionInfoSizeW=C:\\Windows\\System32\\version.GetFileVersionInfoSizeW")
#pragma comment(linker, "/export:GetFileVersionInfoW=C:\\Windows\\System32\\version.GetFileVersionInfoW")
#pragma comment(linker, "/export:VerFindFileA=C:\\Windows\\System32\\version.VerFindFileA")
#pragma comment(linker, "/export:VerFindFileW=C:\\Windows\\System32\\version.VerFindFileW")
#pragma comment(linker, "/export:VerInstallFileA=C:\\Windows\\System32\\version.VerInstallFileA")
#pragma comment(linker, "/export:VerInstallFileW=C:\\Windows\\System32\\version.VerInstallFileW")
#pragma comment(linker, "/export:VerLanguageNameA=C:\\Windows\\System32\\version.VerLanguageNameA")
#pragma comment(linker, "/export:VerLanguageNameW=C:\\Windows\\System32\\version.VerLanguageNameW")
#pragma comment(linker, "/export:VerQueryValueA=C:\\Windows\\System32\\version.VerQueryValueA")
#pragma comment(linker, "/export:VerQueryValueW=C:\\Windows\\System32\\version.VerQueryValueW")

#include <Windows.h>
#include "../MinHook/MinHook.h"

#include <strsafe.h>
#include <string>
#include <vector>
#include <sstream>

#include "Config.h"

// --- 1. Поиск начала функции по сигнатуре внутри нее (Pattern Scan + RtlLookupFunctionEntry) ---
uintptr_t FindFunctionRVA(HMODULE hMod, const char* pattern, uintptr_t fallbackRVA, const wchar_t* funcName) {
    if (!hMod || !pattern || *pattern == '\0') {
        LogToFile(L"[Mabu-rabu] [AutoScan] Invalid arguments for %s, using fallback RVA: 0x%llX", funcName, fallbackRVA);
        return fallbackRVA;
    }

    auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hMod);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return fallbackRVA;
    }

    auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uint8_t*>(hMod) + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return fallbackRVA;
    }
    size_t imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    uint8_t* baseBytes = reinterpret_cast<uint8_t*>(hMod);

    // Парсим строку паттерна вида "48 8B 15 ? ? ? ? B9 04"
    std::vector<int> bytes;
    std::istringstream iss(pattern);
    std::string token;
    while (iss >> token) {
        if (token == "?" || token == "??") {
            bytes.push_back(-1);
        }
        else {
            bytes.push_back(std::stoi(token, nullptr, 16));
        }
    }

    size_t patSize = bytes.size();
    if (patSize == 0 || imageSize < patSize) {
        LogToFile(L"[Mabu-rabu] [AutoScan] Pattern size mismatch for %s, using fallback RVA: 0x%llX", funcName, fallbackRVA);
        return fallbackRVA;
    }
    for (size_t i = 0; i <= imageSize - patSize; ++i) {
        bool found = true;
        for (size_t j = 0; j < patSize; ++j) {
            if (bytes[j] != -1 && baseBytes[i + j] != bytes[j]) {
                found = false;
                break;
            }
        }
        if (found) {
            DWORD64 matchAddr = reinterpret_cast<DWORD64>(baseBytes + i);
            DWORD64 imgBase = 0;
            PRUNTIME_FUNCTION pRuntimeFunc = RtlLookupFunctionEntry(matchAddr, &imgBase, nullptr);
            if (pRuntimeFunc != nullptr) {
                // Идем вверх по цепочке чанков (UNW_FLAG_CHAININFO), если функция разбита компилятором
                while (true) {
                    BYTE* unwindInfo = reinterpret_cast<BYTE*>(imgBase + pRuntimeFunc->UnwindInfoAddress);
                    BYTE flags = unwindInfo[0] >> 3;
                    if ((flags & UNW_FLAG_CHAININFO) == 0) {
                        break; // Нашли корневой пролог функции!
                    }
                    BYTE countOfCodes = unwindInfo[2];
                    // Выравниваем размер массива кодов раскрутки на 2 элемента (4 байта)
                    size_t offset = 4 + ((countOfCodes + 1) & ~1) * 2;
                    pRuntimeFunc = reinterpret_cast<PRUNTIME_FUNCTION>(unwindInfo + offset);
                }

                uintptr_t foundRVA = static_cast<uintptr_t>(pRuntimeFunc->BeginAddress);
                LogToFile(L"[Mabu-rabu] [AutoScan] Found %s at RVA: 0x%llX", funcName, foundRVA);
                return foundRVA;
            }
        }
    }

    LogToFile(L"[Mabu-rabu] [AutoScan] Pattern failed for %s, using fallback RVA: 0x%llX", funcName, fallbackRVA);
    return fallbackRVA;
}

// Вспомогательный поиск без прямых C++-объектов внутри __try
static void* TryFindIL2CPPMethodInternal(HMODULE hMod, const char* namespaze, const char* className, const char* methodName, int argsCount) {
    auto il2cpp_domain_get = reinterpret_cast<void* (*)()>(GetProcAddress(hMod, "il2cpp_domain_get"));
    auto il2cpp_domain_get_assemblies = reinterpret_cast<void** (*)(void*, size_t*)>(GetProcAddress(hMod, "il2cpp_domain_get_assemblies"));
    auto il2cpp_assembly_get_image = reinterpret_cast<void* (*)(void*)>(GetProcAddress(hMod, "il2cpp_assembly_get_image"));
    auto il2cpp_class_from_name = reinterpret_cast<void* (*)(void*, const char*, const char*)>(GetProcAddress(hMod, "il2cpp_class_from_name"));
    auto il2cpp_class_get_method_from_name = reinterpret_cast<void** (*)(void*, const char*, int)>(GetProcAddress(hMod, "il2cpp_class_get_method_from_name"));

    if (!il2cpp_domain_get  || !il2cpp_domain_get_assemblies || !il2cpp_assembly_get_image ||
        !il2cpp_class_from_name || !il2cpp_class_get_method_from_name) {
        return nullptr;
    }

    void* result = nullptr;
    __try {
        void* domain = il2cpp_domain_get();
        if (!domain) return nullptr;


        size_t count = 0;
        void** assemblies = il2cpp_domain_get_assemblies(domain, &count);
        if (assemblies && count > 0) {
            for (size_t i = 0; i < count; ++i) {
                if (!assemblies[i]) continue;
                void* image = il2cpp_assembly_get_image(assemblies[i]);
                if (!image) continue;

                void* klass = il2cpp_class_from_name(image, namespaze, className);
                if (!klass) continue;

                void** methodInfo = il2cpp_class_get_method_from_name(klass, methodName, argsCount);
                if (methodInfo && *methodInfo) {
                    result = *methodInfo;
                    break;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        result = nullptr;
    }

    return result;
}

void* FindMethodViaIL2CPP(HMODULE hMod, const char* namespaze, const char* className, const char* methodName, int argsCount, uintptr_t fallbackRVA) {
    for (int attempt = 0; attempt < 16; ++attempt) {
        if (void* fnPtr = TryFindIL2CPPMethodInternal(hMod, namespaze, className, methodName, argsCount)) {
            uintptr_t rva = reinterpret_cast<uintptr_t>(fnPtr) - reinterpret_cast<uintptr_t>(hMod);
            LogToFile(L"[Mabu-rabu] [IL2CPP] Found %hs.%hs at RVA: 0x%llX (attempt %d)", className, methodName, rva, attempt + 1);
            return fnPtr;
        }
        Sleep(16);
    }

    LogToFile(L"[Mabu-rabu] [IL2CPP] Lookup failed for %hs.%hs, using fallback RVA: 0x%llX", className, methodName, fallbackRVA);
    return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hMod) + fallbackRVA);
}

// Конвертация GamePlatform в BundleConfiguration.BundleTypes
int ToBundleType(GamePlatform platform) {
    switch (platform) {
    case GamePlatform::Steamworks: return 6; // В BundleTypes Steamworks = 6
    case GamePlatform::Nutaku:     return 7; // В BundleTypes Nutaku = 7
    default:                       return static_cast<int>(platform); // 1..5 совпадают
    }
}

//хук на лого эролбаа
typedef void(__fastcall* tFloatingBtnSetVisible)(void* __this, bool visible, const void* method);
tFloatingBtnSetVisible oFloatingBtnSetVisible = nullptr;

typedef void(__fastcall* tFloatingBtnShowEdge)(void* __this, int fromState, const void* method);
tFloatingBtnShowEdge oFloatingBtnShowEdge = nullptr;

void __fastcall hkFloatingBtnShowEdge(void* __this, int fromState, const void* method) {
    if (g_Config.DisableLabsLogo) {
        LogToFile(L"[Mabu-rabu] Blocking Erolabs floating button (ShowAtEdge)");
        if (oFloatingBtnSetVisible) {
            oFloatingBtnSetVisible(__this, false, nullptr);
        }
        return;
    }
    oFloatingBtnShowEdge(__this, fromState, method);
}

// --- Хук на BundleConfiguration.get_GamePlatform ---
typedef int(__fastcall* tBundleGetGamePlatform)(void* __this, const void* method);
tBundleGetGamePlatform oBundleGetGamePlatform = nullptr;

int __fastcall hkBundleGetGamePlatform(void* __this, const void* method) {
    int orig = oBundleGetGamePlatform(__this, method);
    if (g_Config.ForcePlatform) {
        int target = static_cast<int>(g_Config.TargetPlatform);
        if (orig != target) {
            static int logCount = 0;
            if (logCount < 10) {
                LogToFile(L"[Mabu-rabu] Spoofing BundleGamePlatform: %d -> %d", orig, target);
                logCount++;
            }
        }
        return target;
    }
    return orig;
}

// Локальный флаг потока: активен только внутри трех целевых методов
thread_local bool g_SpoofPlatform = false;

// Вспомогательная лямбда или функция для удобного логирования каждого хука
bool CreateAndEnableHook(const wchar_t* name, uintptr_t base, uintptr_t rva, void* detour, void** original) {
    void* target = reinterpret_cast<void*>(base + rva);
    MH_STATUS createStatus = MH_CreateHook(target, detour, original);
    if (createStatus != MH_OK) {
        LogToFile(L"[Mabu-rabu] ERROR: MH_CreateHook failed for %s (RVA: 0x%llX, Addr: 0x%p) | Status: %d",
            name, rva, target, createStatus);
        return false;
    }

    MH_STATUS enableStatus = MH_EnableHook(target);
    if (enableStatus != MH_OK) {
        LogToFile(L"[Mabu-rabu] ERROR: MH_EnableHook failed for %s (Addr: 0x%p) | Status: %d",
            name, target, enableStatus);
        return false;
    }

    LogToFile(L"[Mabu-rabu] SUCCESS: Hooked %s (RVA: 0x%llX, Addr: 0x%p)", name, rva, target);
    return true;
}

// --- 1. Хук на ApplicationConfiguration.get_GamePlatform ---
typedef int(__fastcall* tGetGamePlatform)(void* __this, const void* method);
tGetGamePlatform oGetGamePlatform = nullptr;

typedef void(__fastcall* tUpdateDataModel)(void* __this, void* arguments, const void* method);
tUpdateDataModel oUpdateDataModel = nullptr;

thread_local GamePlatform g_OverridePlatform = GamePlatform::Unknown;

int __fastcall hkGetGamePlatform(void* __this, const void* method) {
    int platform = g_Config.ForcePlatform ? (int)g_Config.TargetPlatform : oGetGamePlatform(__this, method);
    if (platform == 58) return platform; //ehhhhh
    //LogToFile(L"[Mabu-rabu] Spoofing GamePlatform: %d -> %d (g_SpoofPlatform=%d, diff=%d)",
       // platform, GetCockpitPlatform(), (int)g_SpoofPlatform, (int)(platform != GetCockpitPlatform()));
    if (g_SpoofPlatform && platform != GetCockpitPlatform()) {
        static int spoofLogCount = 0;
        if (spoofLogCount < 20) { // Ограничиваем спам в лог первыми 20 срабатываниями
            LogToFile(L"[Mabu-rabu] Spoofing GamePlatform: %d -> %d", platform, GetCockpitPlatform());
            spoofLogCount++;
        }
        return GetCockpitPlatform();
    }
    return platform;
}

void __fastcall hkUpdateDataModel(void* __this, void* arguments, const void* method) {
    static bool logged = false;
    if (!logged) {
        LogToFile(L"[Mabu-rabu] Triggered: BattleController.UpdateDataModel");
        logged = true;
    }
    if (g_Config.Cockpit != ForceMode::Default)
        g_SpoofPlatform = true;
    oUpdateDataModel(__this, arguments, method);
    g_SpoofPlatform = false;
}

typedef void* (__fastcall* tRuntimeDeserialize)(void* __this, void* reader, void* options, const void* method);
tRuntimeDeserialize oRuntimeDeserialize = nullptr;

void* __fastcall hkRuntimeDeserialize(void* __this, void* reader, void* options, const void* method) {
    void* runtimeObj = oRuntimeDeserialize(__this, reader, options, method);

    if (runtimeObj != nullptr) {
        static int callIndex = 0;
        callIndex++;

        bool* pIsRated = reinterpret_cast<bool*>(reinterpret_cast<uintptr_t>(runtimeObj) + 0x10);
        bool orig = *pIsRated;

        // 1-й вызов = rc.neko (управляется X_patch)
        if (callIndex == 1 && g_Config.X_patch != ForceMode::Default) {
            bool target = (g_Config.X_patch == ForceMode::ForceEnable);
            *pIsRated = target;
            LogToFile(L"[Mabu-rabu] [X-patch / rc.neko] Patching IsRated: %d -> %d", (int)orig, (int)target);
        }
        // 2-й вызов = ffs.neko (управляется FullPatch)
        else if (callIndex == 2 && g_Config.FullPatch != ForceMode::Default) {
            bool target = (g_Config.FullPatch == ForceMode::ForceEnable);
            *pIsRated = target;
            LogToFile(L"[Mabu-rabu] [FullPatch / ffs.neko] Patching IsRated: %d -> %d", (int)orig, (int)target);
        }
    }

    return runtimeObj;
}

// --- 3. Обертка для CharacterIllustViewerController.Refresh ---
typedef void(__fastcall* tRefreshIllustViewer)(void* __this, void* args, const void* method);
tRefreshIllustViewer oRefreshIllustViewer = nullptr;

void __fastcall hkRefreshIllustViewer(void* __this, void* args, const void* method) {
    static bool logged = false;
    if (!logged) {
        LogToFile(L"[Mabu-rabu] Triggered: CharacterIllustViewerController.Refresh");
        logged = true;
    }
    if(g_Config.Cockpit !=ForceMode::Default)
        g_SpoofPlatform = true;
    oRefreshIllustViewer(__this, args, method);
    g_SpoofPlatform = false;
}

typedef void* (__fastcall* tCreateAssetEnv)(void* __this, void* assetsUrl, void* staticContentUrl, const void* method);
tCreateAssetEnv oCreateAssetEnv = nullptr;
// Вспомогательная функция чтения Il2CppString* как const wchar_t*
static inline const wchar_t* GetIl2CppStringPtr(void* il2cppStr) {
    if (!il2cppStr) return L"<null>";
    // В 64-битном IL2CPP: +0x10 = int length, +0x14 = wchar_t chars
    return reinterpret_cast<const wchar_t*>(reinterpret_cast<uintptr_t>(il2cppStr) + 0x14);
}

void* __fastcall hkCreateAssetEnv(void* __this, void* assetsUrl, void* staticContentUrl, const void* method) {
    LogToFile(L"[Mabu-rabu] Triggered: EnvironmentService.CreateAssetEnvironmentSettings");

    if (g_Config.FullPatch != ForceMode::Default && __this != nullptr) {
        // Поле private readonly IApplicationConfiguration configuration лежит по смещению +0x10 в EnvironmentService
        uintptr_t appConfig = *reinterpret_cast<uintptr_t*>(reinterpret_cast<uintptr_t>(__this) + 0x10);
        if (appConfig != 0) {
            // Поле <GameRating>k__BackingField лежит по смещению +0x40 (0 = Normal, 1 = Rated)
            int* pGameRating = reinterpret_cast<int*>(appConfig + 0x40);
            int targetRating = (g_Config.FullPatch == ForceMode::ForceEnable) ? 1 : 0;

            if (*pGameRating != targetRating) {
                LogToFile(L"[Mabu-rabu] [FullPatch] Patching ApplicationConfiguration.GameRating (0x%p + 0x40): %d -> %d",
                    reinterpret_cast<void*>(appConfig), *pGameRating, targetRating);
                *pGameRating = targetRating;
            }
        }
    }

    void* result = oCreateAssetEnv(__this, assetsUrl, staticContentUrl, method);

    // Логируем итоговые URL ассетов из AssetEnvironmentSettings (+0x10 и +0x18), чтобы убедиться в смене ветки
    if (result != nullptr) {
        void* bundleUrlObj = *reinterpret_cast<void**>(reinterpret_cast<uintptr_t>(result) + 0x10);
        void* directUrlObj = *reinterpret_cast<void**>(reinterpret_cast<uintptr_t>(result) + 0x18);
        LogToFile(L"[Mabu-rabu] [AssetEnv] BundleAssetUrl: %s", GetIl2CppStringPtr(bundleUrlObj));
        LogToFile(L"[Mabu-rabu] [AssetEnv] DirectAssetUrl: %s", GetIl2CppStringPtr(directUrlObj));
    }

    return result;
}

typedef void* (__fastcall* tBundleDeserialize)(void* __this, void* reader, void* options, const void* method);
tBundleDeserialize oBundleDeserialize = nullptr;

void* __fastcall hkBundleDeserialize(void* __this, void* reader, void* options, const void* method) {
    // Вызываем оригинальную десериализацию bc.neko
    void* bundleObj = oBundleDeserialize(__this, reader, options, method);

    if (g_Config.ForcePlatform && bundleObj != nullptr) {
        // Поле <BundleType>k__BackingField лежит строго по смещению +0x10
        int* pBundleType = reinterpret_cast<int*>(reinterpret_cast<uintptr_t>(bundleObj) + 0x10);
        int origType = *pBundleType;
        int targetType = ToBundleType(g_Config.TargetPlatform);
        *pBundleType = targetType;
        LogToFile(L"[Mabu-rabu] [ForcePlatform / bc.neko] Patching BundleType: %d -> %d", origType, targetType);
    }

    return bundleObj;
}

// Сюда переносим установку всех IL2CPP-хуков — она выполнится в главном потоке Unity!
void OnIL2CPPInitialized(HMODULE hGameAssembly) {
    LogToFile(L"[Mabu-rabu] Inside hk_il2cpp_init (Main Thread). Setting up hooks...");

    auto HookIL2CPP = [&](const char* ns, const char* cls, const char* method, uintptr_t fallbackRVA, void* detour, void** original, int argsCount = 0) {
        void* target = FindMethodViaIL2CPP(hGameAssembly, ns, cls, method, argsCount, fallbackRVA);
        if (!target) {
            LogToFile(L"[Mabu-rabu] ERROR: Method not found: %hs.%hs::%hs\n", ns, cls, method);
            return;
        }
        MH_STATUS stCreate = MH_CreateHook(target, detour, original);
        MH_STATUS stEnable = (stCreate == MH_OK) ? MH_EnableHook(target) : stCreate;
        if (stCreate == MH_OK && stEnable == MH_OK) {
            LogToFile(L"[Mabu-rabu] SUCCESS: Hooked %hs.%hs at 0x%p", cls, method, target);
        }
        else {
            LogToFile(L"[Mabu-rabu] ERROR: Failed to hook %hs.%hs | Create: %d, Enable: %d", cls, method, stCreate, stEnable);
        }
        };

    // Теперь можно безопасно искать сколь угодно много классов и методов по именам!
    HookIL2CPP("Assets.Platform", "BundleConfiguration", "get_GamePlatform", RVA_BUNDLE_GET_PLATFORM, &hkBundleGetGamePlatform, reinterpret_cast<void**>(&oBundleGetGamePlatform));

    HookIL2CPP("Assets.GameUi.Services", "EnvironmentService", "CreateAssetEnvironmentSettings", RVA_CREATE_ASSET_ENV, &hkCreateAssetEnv, reinterpret_cast<void**>(&oCreateAssetEnv), 2);

    // Сюда же можно перенести и остальные хуки (или оставить их здесь)
    uintptr_t base = reinterpret_cast<uintptr_t>(hGameAssembly);
  
    // 1. Хук на десериализатор bc.neko (заменяет правку файла на диске)
    CreateAndEnableHook(L"BundleConfigurationFormatter.Deserialize", base, RVA_BUNDLE_DESERIALIZE, &hkBundleDeserialize, reinterpret_cast<void**>(&oBundleDeserialize));

    // 2. Хук на ApplicationConfiguration.get_GamePlatform
    HookIL2CPP("Assets.Configuration", "ApplicationConfiguration", "get_GamePlatform", RVA_GET_GAME_PLATFORM, &hkGetGamePlatform, reinterpret_cast<void**>(&oGetGamePlatform));

    uintptr_t rvaUpdateDataModel = FindFunctionRVA(hGameAssembly, PAT_UPDATE_DATA_MODEL, RVA_UPDATE_DATA_MODEL, L"BattleController.UpdateDataModel");
    uintptr_t rvaRefreshViewer = FindFunctionRVA(hGameAssembly, PAT_REFRESH_VIEWER, RVA_REFRESH_ILLUST_VIEWER, L"CharacterIllustViewerController.Refresh");

    //3. кокпит
    CreateAndEnableHook(L"BattleController.UpdateDataModel", base, rvaUpdateDataModel, &hkUpdateDataModel, reinterpret_cast<void**>(&oUpdateDataModel));
    CreateAndEnableHook(L"CharacterIllustViewerController.Refresh", base, rvaRefreshViewer, &hkRefreshIllustViewer, reinterpret_cast<void**>(&oRefreshIllustViewer));

    //4. цензура
    CreateAndEnableHook(L"RuntimeConfigurationFormatter.Deserialize", base, RVA_RUNTIME_DESERIALIZE, &hkRuntimeDeserialize, reinterpret_cast<void**>(&oRuntimeDeserialize));

    //5 Lab circle annihilation cannon
    //In the name of clean screenshots
    HookIL2CPP("Erolabs.Sdk", "FloatingButtonPresenter", "ShowAtEdge", RVA_EROLABS_BTN_SHOW_EDGE, &hkFloatingBtnShowEdge, reinterpret_cast<void**>(&oFloatingBtnShowEdge), 1);


    // ...
}

typedef int(__fastcall* t_il2cpp_init)(const char* domain_name);
t_il2cpp_init o_il2cpp_init = nullptr;

typedef int(__fastcall* t_il2cpp_init_utf16)(const wchar_t* domain_name);
t_il2cpp_init_utf16 o_il2cpp_init_utf16 = nullptr;

static bool s_HooksInstalled = false;

void RunOnceOnIL2CPPInit() {
    if (s_HooksInstalled) return;
    s_HooksInstalled = true;

    if (HMODULE hGameAssembly = GetModuleHandleA("GameAssembly.dll")) {
        OnIL2CPPInitialized(hGameAssembly);
    }
}

int __fastcall hk_il2cpp_init(const char* domain_name) {
    int res = o_il2cpp_init ? o_il2cpp_init(domain_name) : 0;
    RunOnceOnIL2CPPInit();
    return res;
}

int __fastcall hk_il2cpp_init_utf16(const wchar_t* domain_name) {
    int res = o_il2cpp_init_utf16 ? o_il2cpp_init_utf16(domain_name) : 0;
    RunOnceOnIL2CPPInit();
    return res;
}

// --- Хук на LoadLibraryExW для мгновенного перехвата GameAssembly.dll ---
// Целевой адрес LoadLibraryExW из kernelbase.dll и указатель на оригинал
static void* g_LoadLibraryExWTarget = nullptr;

typedef HMODULE(WINAPI* tLoadLibraryExW)(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
static tLoadLibraryExW oLoadLibraryExW = nullptr;

static void HookIl2CppInitFunction(HMODULE hGameAssembly, const char* procName, void* detour, void** original) {
    void* target = reinterpret_cast<void*>(GetProcAddress(hGameAssembly, procName));
    if (!target) {
        LogToFile(L"[Mabu-rabu] Export not found: %hs", procName);
        return;
    }

    MH_STATUS stCreate = MH_CreateHook(target, detour, original);
    if (stCreate != MH_OK) {
        LogToFile(L"[Mabu-rabu] ERROR: MH_CreateHook failed for %hs (Status: %d)", procName, stCreate);
        return;
    }

    MH_STATUS stEnable = MH_EnableHook(target);
    if (stEnable != MH_OK) {
        LogToFile(L"[Mabu-rabu] ERROR: MH_EnableHook failed for %hs (Status: %d)", procName, stEnable);
        return;
    }

    LogToFile(L"[Mabu-rabu] Hooked %hs at 0x%p", procName, target);
}

static bool ContainsGameAssemblyName(LPCWSTR fileName) {
    if (!fileName) {
        return false;
    }

    // Проверяем имя файла без учёта регистра (на случай GameAssembly.dll / gameassembly.dll)
    const wchar_t* targetName = L"GameAssembly.dll";
    const size_t targetLen = wcslen(targetName);
    const size_t pathLen = wcslen(fileName);

    if (pathLen < targetLen) {
        return false;
    }

    return _wcsicmp(fileName + pathLen - targetLen, targetName) == 0;
}

HMODULE WINAPI hkLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
    HMODULE hMod = oLoadLibraryExW ? oLoadLibraryExW(lpLibFileName, hFile, dwFlags) : nullptr;

    static std::atomic<bool> s_Il2CppHooked{ false };
    if (hMod != nullptr && ContainsGameAssemblyName(lpLibFileName)) {
        bool expected = false;
        if (s_Il2CppHooked.compare_exchange_strong(expected, true)) {
            LogToFile(L"[Mabu-rabu] GameAssembly.dll loaded at 0x%p. Hooking il2cpp_init...", hMod);

            HookIl2CppInitFunction(
                hMod,
                "il2cpp_init",
                reinterpret_cast<void*>(&hk_il2cpp_init),
                reinterpret_cast<void**>(&o_il2cpp_init)
            );

            HookIl2CppInitFunction(
                hMod,
                "il2cpp_init_utf16",
                reinterpret_cast<void*>(&hk_il2cpp_init_utf16),
                reinterpret_cast<void**>(&o_il2cpp_init_utf16)
            );

            // Отключаем только сам хук LoadLibraryExW по реальному целевому адресу
            if (g_LoadLibraryExWTarget != nullptr) {
                MH_STATUS stDisable = MH_DisableHook(g_LoadLibraryExWTarget);
                if (stDisable == MH_OK) {
                    LogToFile(L"[Mabu-rabu] Disabled LoadLibraryExW hook");
                }
                else {
                    LogToFile(L"[Mabu-rabu] WARNING: Failed to disable LoadLibraryExW hook (Status: %d)", stDisable);
                }
            }
        }
    }

    return hMod;
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        wchar_t exePath[MAX_PATH] = { 0 };
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        if (wcsstr(exePath, L"muv_luv_girlsgarden_cl.exe") == nullptr) {
            return TRUE;
        }

        RotateLogFile();

        LoadConfig();
        EnsureFfsNekoExists();
        LogToFile(L"[Mabu-rabu] DLL_PROCESS_ATTACH in game process. Hooking LoadLibraryExW...");

        MH_Initialize();
        // В DllMain вместо MH_CreateHook(&LoadLibraryExW, ...):
        if (HMODULE hKernelBase = GetModuleHandleW(L"kernelbase.dll")) {
            g_LoadLibraryExWTarget = reinterpret_cast<void*>(GetProcAddress(hKernelBase, "LoadLibraryExW"));
        }

        if (g_LoadLibraryExWTarget != nullptr) {
            MH_STATUS stCreate = MH_CreateHook(
                g_LoadLibraryExWTarget,
                reinterpret_cast<void*>(&hkLoadLibraryExW),
                reinterpret_cast<void**>(&oLoadLibraryExW)
            );
            if (stCreate == MH_OK) {
                MH_EnableHook(g_LoadLibraryExWTarget);
            }
        }
        MH_EnableHook(MH_ALL_HOOKS);
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
    }
    return TRUE;
}
