import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import games


class GamesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def touch(self, name, content=b"fixture"):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        return target

    def manifest(self, appid, name, folder, flags="4"):
        return self.touch(f"steam/steamapps/appmanifest_{appid}.acf", (
            '"AppState" { "appid" "' + appid + '" "name" "' + name +
            '" "installdir" "' + folder + '" "StateFlags" "' + flags +
            '" "buildid" "123" }').encode())

    def test_vdf_nested_paths_comments_and_invalid_input(self):
        record = games.parse_vdf('"libraryfolders" { // comment\n "0" { "path" "F:\\\\SteamLibrary" } }')
        self.assertEqual(record["libraryfolders"]["0"]["path"], "F:\\SteamLibrary")
        for malformed in ['"a" { "b" "c"', '"a"', '}', '"a" "unterminated']:
            with self.assertRaises(ValueError):
                games.parse_vdf(malformed)

    def test_engine_evidence_and_stable_identity(self):
        self.touch("mono/Fish_Data/Managed/Assembly-CSharp.dll")
        self.assertEqual(games.inspect_game(self.root / "mono")["engine"], "unity-mono")
        self.touch("nested/PlateUp/PlateUp_Data/Managed/Assembly-CSharp.dll")
        self.assertEqual(games.inspect_game(self.root / "nested")["engine"], "unity-mono")
        self.touch("il2cpp/GameAssembly.dll")
        self.touch("il2cpp/Fish_Data/il2cpp_data/Metadata/global-metadata.dat")
        result = games.inspect_game(self.root / "il2cpp")
        self.assertEqual(result["engine"], "unity-il2cpp")
        self.assertEqual(len(result["engine_evidence"]), 2)
        self.assertEqual(result["id"], games.inspect_game(self.root / "il2cpp", "other title")["id"])
        self.touch("unreal/Project/Content/Paks/main.pak")
        (self.root / "unreal/Project/Binaries/Win64").mkdir(parents=True)
        self.assertEqual(games.inspect_game(self.root / "unreal")["engine"], "unreal")
        self.touch("devkit/UDKGame/CookedPCConsole/Map.udk")
        self.assertEqual(games.inspect_game(self.root / "devkit")["engine"], "unreal")
        self.touch("godot/game.pck", b"GDPCdata")
        self.assertEqual(games.inspect_game(self.root / "godot")["engine"], "godot")
        self.touch("native/game.exe", b"MZ")
        self.assertEqual(games.inspect_game(self.root / "native")["engine"], "native")
        self.assertFalse(games.inspect_game(self.root / "absent")["installed"])

    def test_steam_readiness_missing_paths_and_manifest_traversal(self):
        self.touch("steam/steamapps/common/Ready/game.exe")
        self.touch("steam/steamapps/common/Pending/game.exe")
        self.manifest("10", "Ready game", "Ready")
        self.manifest("20", "Pending game", "Pending", str(4 | 1048576))
        self.manifest("30", "Missing game", "Missing")
        self.manifest("40", "Invalid path", "../escape")
        result = games.steam_games([self.root / "steam"])
        by_id = {row["launcher_id"]: row for row in result}
        self.assertEqual(set(by_id), {"10", "20", "30"})
        self.assertTrue(by_id["10"]["installed"])
        self.assertFalse(by_id["20"]["installed"])
        self.assertEqual(by_id["20"]["installation_status"], "updating")
        self.assertEqual(by_id["30"]["installation_status"], "missing")

    def test_epic_incomplete_and_dlc_filter(self):
        location = self.touch("epic-game/game.exe").parent
        self.touch("manifests/game.item", json.dumps({"AppName": "game-id", "DisplayName": "Game",
            "InstallLocation": str(location), "bIsIncompleteInstall": True}).encode())
        self.touch("manifests/dlc.item", json.dumps({"AppName": "dlc", "InstallLocation": str(location), "bIsDLC": True}).encode())
        self.touch("manifests/editor.item", json.dumps({"AppName": "UE_5.8", "InstallLocation": str(location), "bIsApplication": False}).encode())
        result = games.epic_games(self.root / "manifests")
        self.assertEqual(len(result), 1)
        self.assertFalse(result[0]["installed"])
        self.assertEqual(result[0]["installation_status"], "incomplete")

    def test_discovery_deduplicates_same_path_and_prefers_ready_copy(self):
        self.touch("game/game.exe")
        first = games.inspect_game(self.root / "game", "Same", "Steam")
        first["installed"] = False
        second = games.inspect_game(self.root / "game", "Same", "Epic")
        with patch.object(games, "_steam_roots", return_value=[]), \
                patch.object(games, "steam_games", return_value=[first]), \
                patch.object(games, "epic_games", return_value=[second]), \
                patch.object(games, "_gog_games", return_value=[]):
            result = games.discover_games()
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]["installed"])
        self.assertEqual(result[0]["launcher"], "Epic")

    def test_oversize_manifest_rejected(self):
        self.touch("too-large.acf", b"x" * (games.MAX_MANIFEST_BYTES + 1))
        with self.assertRaises(ValueError):
            games._read(self.root / "too-large.acf")


if __name__ == "__main__":
    unittest.main()
