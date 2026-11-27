#include "pch.h"
#include "Config.h"
#include <Windows.h>
#include <strsafe.h>

static std::wstring GetBaseDir() {
    wchar_t path[MAX_PATH] = { 0 };
    GetModuleFileNameW(nullptr, path, MAX_PATH);// Путь к .exe игры
    std::wstring dir(path);
    size_t pos = dir.find_last_of(L"\\/");
    return (pos != std::wstring::npos) ? dir.substr(0, pos + 1) : L"";
}

//forcing data change without this stupid file is insanely complicated
//so.... we create one and then hook function that will read it
void EnsureFfsNekoExists() {
    if (g_Config.FullPatch == ForceMode::Default) {
        return;
    }

    std::wstring ffsPath = GetBaseDir() + L"muv_luv_girlsgarden_cl_Data\\StreamingAssets\\ffs.neko";

    if (GetFileAttributesW(ffsPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        return;
    }

    HANDLE hFile = CreateFileW(
        ffsPath.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        const BYTE defaultFalseData[] = { 0x91, 0xC2 }; // MessagePack: [false]
        DWORD bytesWritten = 0;
        WriteFile(hFile, defaultFalseData, sizeof(defaultFalseData), &bytesWritten, nullptr);
        CloseHandle(hFile);
        LogToFile(L"[Mabu-rabu] [FullPatch] Created default ffs.neko (0x91 0xC2) at: %s", ffsPath.c_str());
    }
    else {
        LogToFile(L"[Mabu-rabu] [FullPatch] ERROR: Failed to create ffs.neko! GetLastError: %lu", GetLastError());
    }
}

static std::wstring GetLogPath() {
    return GetBaseDir() + L"MabuRabu_GG_Xlocker_Log.txt";
}

// Вспомогательная функция для генерации чистого конфига с комментариями
static void CreateDefaultConfig(const std::wstring& iniPath) {
    HANDLE hFile = CreateFileW(
        iniPath.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_NEW, // Создаст файл только если его еще нет
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        const char* defaultIni =
            "[Settings]\r\n"
            "; Cockpit camera mode (0 = do nothing, 1 = force enable, 2 = force disable)\r\n"
            "Cockpit=1\r\n"
            "\r\n"
            "; Enable change of client (0 = do nothing, 1 = force flatform)\r\n"
            "ForcePlatform=0\r\n"
            "\r\n"
            "; Choose client when ForcePlatform=1:\r\n"
            "; 1 = DMM, 2 = GooglePlay, 3 = AppStore, 4 = Johren, 5 = Erolabs, 6 = Nutaku, 7 = Steamworks\r\n"
            "TargetPlatform=5\r\n"
            "; similar to changing bc.neko file\r\n"
            "\r\n"
            "; Cultured patch (0 = do nothing, 1 = force enable, 2 = force disable)\r\n"
            "X-patch=0\r\n"
            "; same as changing rc.neko file. Censored EroLab. . . Why not?\r\n"
            "\r\n"
            "; Full patch / restore altered assets (0 = do nothing, 1 = force enable, 2 = force disable)\r\n"
            "FullPatch=0\r\n"
            "; same as changing ffs.neko file. No effect on EroLab\r\n"
            "\r\n"
            "; Annoyed by EroLabs circle on your screen? (0 = do nothing, 1 = circle begone)\r\n"
            "LabsLogo=0\r\n"
            "\r\n"
            "; Enable debug logging to MabuRabu_GG_Xlocker_Log.txt (0 = disabled, 1 = enabled)\r\n"
            "; Most users don't need that\r\n"
            "EnableLog=0\r\n";


        DWORD bytesWritten = 0;
        WriteFile(hFile, defaultIni, static_cast<DWORD>(strlen(defaultIni)), &bytesWritten, nullptr);
        CloseHandle(hFile);
    }
}

void LoadConfig() {
    std::wstring iniPath = GetBaseDir() + L"MabuRabu_GG_Xlocker.ini";

    if (GetFileAttributesW(iniPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        CreateDefaultConfig(iniPath);
    }

    // 1. Логирование (0..1)
    int rawLog = GetPrivateProfileIntW(L"Settings", L"EnableLog", 0, iniPath.c_str());
    int cleanLog = SanitizeRange(rawLog, 0, 1);
    g_Config.EnableLog = (cleanLog == 1);

    // 2. Режим кокпита (0..2)
    int rawCockpit = GetPrivateProfileIntW(L"Settings", L"Cockpit", static_cast<int>(ForceMode::ForceEnable), iniPath.c_str());
    int cleanCockpit = SanitizeRange(rawCockpit, static_cast<int>(ForceMode::Default), static_cast<int>(ForceMode::ForceDisable));
    if (cleanCockpit != -1) {
        g_Config.Cockpit = static_cast<ForceMode>(cleanCockpit);
    }
    else {
        LogToFile(L"[Mabu-rabu] [Config] Invalid Cockpit mode: %d. Falling back to Default (0).", rawCockpit);
        g_Config.Cockpit = ForceMode::Default;
    }

    // 3. Глобальный форс платформы (0..1)
    int rawForce = GetPrivateProfileIntW(L"Settings", L"ForcePlatform", 0, iniPath.c_str());
    int cleanForce = SanitizeRange(rawForce, 0, 1);
    if (cleanForce != -1) {
        g_Config.ForcePlatform = (cleanForce == 1);
    }
    else {
        LogToFile(L"[Mabu-rabu] [Config] Invalid ForcePlatform value: %d. Disabling.", rawForce);
        g_Config.ForcePlatform = false;
    }

    // 4. Целевая платформа (1..7)
    int rawPlatform = GetPrivateProfileIntW(L"Settings", L"TargetPlatform", static_cast<int>(GamePlatform::Erolabs), iniPath.c_str());
    int cleanPlatform = SanitizeRange(rawPlatform, static_cast<int>(GamePlatform::Dmm), static_cast<int>(GamePlatform::Steamworks));
    if (cleanPlatform != -1) {
        g_Config.TargetPlatform = static_cast<GamePlatform>(cleanPlatform);
    }
    else {
        LogToFile(L"[Mabu-rabu] [Config] Provided invalid platform: %d. Disabling ForcePlatform.", rawPlatform);
        g_Config.ForcePlatform = false;
    }


    // 5. X_patch (0..2)
    int rawXPatch = GetPrivateProfileIntW(L"Settings", L"X-patch", static_cast<int>(ForceMode::Default), iniPath.c_str());
    int cleanXPatch = SanitizeRange(rawXPatch, static_cast<int>(ForceMode::Default), static_cast<int>(ForceMode::ForceDisable));
    if (cleanXPatch != -1) {
        g_Config.X_patch = static_cast<ForceMode>(cleanXPatch);
    }
    else {
        LogToFile(L"[Mabu-rabu] [Config] Invalid X_patch value: %d. Falling back to Default (0).", rawXPatch);
        g_Config.X_patch = ForceMode::Default;
    }

    // 6. FullPatch (0..2)
    int rawFullPatch = GetPrivateProfileIntW(L"Settings", L"FullPatch", static_cast<int>(ForceMode::Default), iniPath.c_str());
    int cleanFullPatch = SanitizeRange(rawFullPatch, static_cast<int>(ForceMode::Default), static_cast<int>(ForceMode::ForceDisable));
    if (cleanFullPatch != -1) {
        g_Config.FullPatch = static_cast<ForceMode>(cleanFullPatch);
    }
    else {
        LogToFile(L"[Mabu-rabu] [Config] Invalid FullPatch value: %d. Falling back to Default (0).", rawFullPatch);
        g_Config.FullPatch = ForceMode::Default;
    }

    // 7. Удаляем лого (0..1)
    int rawLogo = GetPrivateProfileIntW(L"Settings", L"LabsLogo", 0, iniPath.c_str());
    int cleanLogo = SanitizeRange(rawLogo, 0, 1);
    if (cleanLogo != -1) {
        g_Config.DisableLabsLogo = (cleanLogo == 1);
    }
    else {
        LogToFile(L"[Mabu-rabu] [Config] Invalid LabsLogo value: %d. Disabling.", rawLogo);
        g_Config.DisableLabsLogo = false;
    }
}

void RotateLogFile() {
    std::wstring logPath = GetLogPath();
    std::wstring bakPath = logPath + L".bak";
    // Перемещаем старый лог в .bak с заменой существующего
    MoveFileExW(logPath.c_str(), bakPath.c_str(), MOVEFILE_REPLACE_EXISTING);
}

void LogToFile(const wchar_t* format, ...) {
    if (!g_Config.EnableLog || format == nullptr) return;

    static const std::wstring logPath = GetLogPath();

    va_list args;
    va_start(args, format);

    va_list argsCopy;
    va_copy(argsCopy, args);
    int len = _vscwprintf(format, argsCopy);
    va_end(argsCopy);

    if (len <= 0) {
        va_end(args);
        return;
    }

    std::wstring message(static_cast<size_t>(len), L'\0');
    int writtenChars = _vsnwprintf_s(message.data(), message.size() + 1, _TRUNCATE, format, args);
    va_end(args);

    if (writtenChars <= 0) {
        return;
    }

    message.resize(static_cast<size_t>(writtenChars));
    message += L"\r\n";

    int utf8Len = WideCharToMultiByte(
        CP_UTF8, 0,
        message.c_str(), static_cast<int>(message.size()),
        nullptr, 0, nullptr, nullptr
    );
    if (utf8Len <= 0) {
        return;
    }

    std::string utf8Buffer(static_cast<size_t>(utf8Len), '\0');
    int converted = WideCharToMultiByte(
        CP_UTF8, 0,
        message.c_str(), static_cast<int>(message.size()),
        utf8Buffer.data(), utf8Len, nullptr, nullptr
    );
    if (converted <= 0) {
        return;
    }
    // Открываем файл строго в режиме добавления (Thread-safe append)
    HANDLE hFile = CreateFileW(
        logPath.c_str(),
        FILE_APPEND_DATA,
        FILE_SHARE_READ,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten = 0;
        WriteFile(
            hFile,
            utf8Buffer.data(),
            static_cast<DWORD>(converted),
            &bytesWritten,
            nullptr
        );
        CloseHandle(hFile);
    }
}
