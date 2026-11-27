#pragma once
#include <string>

// Смещения (RVA) из dump.cs для текущей сборки GameAssembly.dll
constexpr uintptr_t RVA_GET_GAME_PLATFORM = 0x89B620;  // ApplicationConfiguration.get_GamePlatform
constexpr uintptr_t RVA_UPDATE_DATA_MODEL = 0xBF2890;  // BattleController.UpdateDataModel
constexpr uintptr_t RVA_REFRESH_ILLUST_VIEWER = 0x1C794B0; // CharacterIllustViewerController.Refresh
constexpr uintptr_t RVA_CREATE_ASSET_ENV = 0x1510120; // EnvironmentService.CreateAssetEnvironmentSettings

// RVA из дампа 
//constexpr uintptr_t RVA_BUNDLE_GET_TYPE = 0x858320;  // BundleConfiguration.get_BundleType
constexpr uintptr_t RVA_BUNDLE_GET_PLATFORM = 0x12CA920; // BundleConfiguration.get_GamePlatform
constexpr uintptr_t RVA_BUNDLE_DESERIALIZE = 0x4A8C9E0; // BundleConfigurationFormatter.Deserialize
constexpr uintptr_t RVA_RUNTIME_DESERIALIZE = 0x12222B0; // RuntimeConfigurationFormatter.Deserialize
constexpr uintptr_t RVA_EROLABS_BTN_SHOW_EDGE = 0x12D00E0; // Erolabs.Sdk.FloatingButtonPresenter.ShowAtEdge
constexpr uintptr_t RVA_READ_RUNTIME_CFG = 0x4A94D70; // Platform.ReadRuntimeConfigurationFromStreamingAssets

// Сигнатуры из Python-скрипта
inline const char* PAT_UPDATE_DATA_MODEL = "48 8B 15 ? ? ? ? B9 04 00 00 00 E8 ? ? ? ? 83 F8 03 0F 84 ? ? ? ? 4C 8B 86 ? ? ? ? 4D 85 C0 0F 84 ? ? ? ? 48 8B 15 ? ? ? ? B9 04 00 00 00 E8 ? ? ? ? 83 F8 07 41 0F 94 C1";
inline const char* PAT_REFRESH_VIEWER = "48 8B 15 ? ? ? ? B9 04 00 00 00 E8 ? ? ? ? 83 F8 02 74 ? 4C 8B 85 ? ? ? ? 4D 85 C0 0F 84 ? ? ? ? 48 8B 15 ? ? ? ? B9 04 00 00 00 E8 ? ? ? ? 83 F8 07 41 0F 95 C4";
inline const char* PAT_CREATE_ASSET_ENV = "B9 04 00 00 00 48 8B 15 ? ? ? ? E8 ? ? ? ? 8D 48 FF 48 8D 35 ? ? ? ? 83 F9 06 77 ? FF C8 48 63 C8";

// Точное соответствие enum Assets.Configuration.GamePlatforms из игры
enum class BundleType : int {
    Unknown = 0,
    Dmm = 1,
    GooglePlay = 2,
    AppStore = 3,
    Johren = 4,
    Erolabs = 5,
    Steamworks = 6,
    Nutaku = 7
};

// Точное соответствие enum Assets.Configuration.GamePlatforms из игры
enum class GamePlatform : int {
    Unknown = 0,
    Dmm = 1,
    GooglePlay = 2,
    AppStore = 3,
    Johren = 4,
    Erolabs = 5,
    Nutaku = 6,
    Steamworks = 7
};

enum class ForceMode : int {
    Default = 0, // Ничего не менять
    ForceEnable = 1, // Принудительно включить
    ForceDisable = 2  // Принудительно выключить
};

struct ModConfig {
    bool EnableLog = false;

    ForceMode Cockpit = ForceMode::ForceEnable; // По умолчанию 1 (включить кокпит)

    bool ForcePlatform  = false;
    GamePlatform TargetPlatform = GamePlatform::Erolabs;

    ForceMode X_patch = ForceMode::Default; 

    ForceMode FullPatch = ForceMode::Default; 

    bool DisableLabsLogo = false;
};

inline ModConfig g_Config;

void EnsureFfsNekoExists();
void LoadConfig();
void RotateLogFile();
void LogToFile(const wchar_t* format, ...);

inline int GetCockpitPlatform() {
    // Вычислится ровно 1 раз при самом первом вызове, дальше будет просто отдавать готовый int
    static const int cachedPlatform = (g_Config.Cockpit == ForceMode::ForceEnable)
        ? (int)GamePlatform::Erolabs
        : (int)GamePlatform::Steamworks;

    return cachedPlatform;
}

constexpr int SanitizeRange(int value, int minVal, int maxVal) noexcept {
    return (value >= minVal && value <= maxVal) ? value : -1;
}