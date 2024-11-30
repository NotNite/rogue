from .settings import settings, GAME_DIR, HELPER_EXE
import os
import json
import subprocess


def run(args: list[str]) -> bytes:
    game_dir = settings.get_string(GAME_DIR)
    if not game_dir:
        raise ValueError("Game directory not set")

    sqpack_path = os.path.join(game_dir, "sqpack")
    helper_exe = settings.get_string(HELPER_EXE)
    if not helper_exe:
        raise ValueError("Helper executable not set")

    real_args = [helper_exe, sqpack_path] + args
    process = subprocess.run(real_args, capture_output=True, shell=True)
    return process.stdout


def sheet(name: str, row: int = None) -> list[dict]:
    args = ["sheet", name]
    if row:
        args.append(str(row))
    bytes = run(args)
    return json.loads(bytes)
