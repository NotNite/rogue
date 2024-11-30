from binaryninja import Settings
import json

GAME_DIR = "rogue.game_dir"
CS_DIR = "rogue.cs_dir"
HELPER_EXE = "rogue.helper_exe"


def register(key: str, title: str, description: str, type: str, default):
    settings.register_setting(
        key,
        json.dumps(
            {
                "title": title,
                "description": description,
                "type": type,
                "default": default,
                # wtf does this do lol https://api.binary.ninja/binaryninja.settings-module.html
                "ignore": ["SettingsProjectScope", "SettingsResourceScope"],
            }
        ),
    )


settings = Settings()
settings.register_group("rogue", "Rogue")

register(
    GAME_DIR,
    "Game Directory",
    "The folder that contains the game executable and sqpack folder",
    "string",
    None,
)

register(
    CS_DIR,
    "ClientStructs Directory",
    "The folder that you cloned FFXIVClientStructs into",
    "string",
    None,
)

register(
    HELPER_EXE, "Helper Executable", "The path to the helper executable", "string", None
)
