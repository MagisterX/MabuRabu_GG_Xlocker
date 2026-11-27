# MabuRabu GG Xlocker

A lightweight `version.dll` proxy plugin for **Girls Garden** that unlocks platform-restricted features in memory without modifying original game files.

## Features

* **Independent Cockpit Camera Control**: Force-enable the cockpit camera view in battles onrestricted platforms (such as Steam), or force-disable it on uncensored clients (why not?).
* **Selection of client platform**: Switch between (DMM, Erolabs, Steamworks, Nutaku, etc.) without manually hex-editing `bc.neko`. Only EroLas and Steam were tested.
* **X-patch**: Self-explanatory. Similar to editing (`rc.neko`) file.
* **Full Patch**: Restore altered assets on steam version. Similar to (`ffs.neko`) file.
* **Hide EroLabs Logo**: Can hide that annoying circle that plagues your screenshots.
* **Update-Resilient Hooking**: Should be working even if game updates. Thanks to programming mumbo-jumbo such as hooking into IL2CPP functions.

---

## Installation

1. Download the latest `version.dll` from the [Releases](../../releases) page (or build it yourself).
2. Place `version.dll` into your game's root directory next to `muv_luv_girlsgarden_cl.exe`:
   ```text
   ...\Steam\steamapps\common\マブラヴ ガールズガーデン\version.dll
   ```
3. Launch the game once. A default configuration file `MabuRabu_GG_Xlocker.ini` will be generated automatically in the same folder.
4. Open `MabuRabu_GG_Xlocker.ini` with any text editor to adjust your preferences, then restart the game.

### Uninstallation
Simply delete `version.dll` (and optionally `MabuRabu_GG_Xlocker.ini` / `MabuRabu_GG_Xlocker_Log.txt`) from the game folder. No original game files are ever modified on disk.

---

## Building from Source

### Prerequisites
* Windows 10/11 SDK
* Visual Studio 2022 with **Desktop development with C++** workload
* [MinHook](https://github.com/tsudakageyu/minhook) (included in the project)

### Build Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/MagisterX/MabuRabu_GG_Xlocker.git
   ```
2. Open the `.sln` solution file in Visual Studio 2022.
3. Make sure **`Release`** and **`x64`** are selected.
4. Build the solution. The compiled `Mabu-rabu.dll` will need to be renamed as `version.dll`.
5. Place version.dll into game folder right next to 'muv_luv_girlsgarden_cl.exe'.
---

## Credits

* [Renari](https://gist.github.com/Renari/9620aedb70b3827477432eab94e2da70) — for finding the original AOB signatures, reverse-engineering the initial game logic, and laying the groundwork for this project.
* Hooking powered by [MinHook](https://github.com/tsudakageyu/minhook) by Tsuda Kageyu (BSD 2-Clause License).
