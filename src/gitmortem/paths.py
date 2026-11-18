from pathlib import Path

import platformdirs


def default_data_dir() -> Path:
    return platformdirs.user_data_path("GitMortem", appauthor=False)


def default_key_file() -> Path:
    return platformdirs.user_config_path("GitMortem", appauthor=False) / "instance.key"
