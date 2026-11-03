"""Command-line options and portable per-mode settings."""

import argparse
import json
import sys
from pathlib import Path
from tempfile import NamedTemporaryFile

from update_check import CURRENT_VERSION

_LIVE_ONLY = {"rerun_mode", "poll_interval"}
_RERUN_MODES = ("once", "prompt", "daemon")


def _config_path() -> Path:
    entry = sys.executable if getattr(sys, "frozen", False) else __file__
    return Path(entry).resolve().with_name("config.json")


def _read_config(path: Path) -> dict[str, object]:
    try:
        # Accept an optional editor-added BOM; write plain UTF-8.
        with path.open(encoding="utf-8-sig") as stream:
            config = json.load(stream)
    except FileNotFoundError:
        return {"generated_with": CURRENT_VERSION}

    if not isinstance(config, dict):
        raise ValueError("expected a JSON object")

    return config


def _write_config(path: Path, config: dict[str, object]) -> None:
    with NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete_on_close=False) as stream:
        temporary = Path(stream.name)
        json.dump(config, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
        stream.close()
        temporary.replace(path)


def _setting_help(action: argparse.Action, default: object) -> str:
    description = (action.help or "").rstrip(".")
    if action.choices is not None:
        description += f". Values: {', '.join(action.choices)}"
    elif isinstance(default, bool):
        description += ". Values: true, false"
    elif action.dest == "metadata_path":
        description += ". Use null for automatic discovery"
    elif action.dest == "poll_interval":
        description += ". Must be a positive finite number"

    return f"{description}. Default: {json.dumps(default)}."


def _backfill_config(config: dict[str, object], mode_settings: dict[str, dict[argparse.Action, object]]) -> bool:
    changed = False
    help_text: dict[str, str] = {}
    for mode, settings in mode_settings.items():
        if mode not in config:
            config[mode] = {}
            changed = True
        section = config[mode]

        for action, default in settings.items():
            key = action.dest
            help_text[f"{mode}.{key}"] = _setting_help(action, default)
            if isinstance(section, dict) and key not in section:
                section[key] = default
                changed = True

    if changed or "_help" not in config:
        config["_help"] = help_text
        return True
    return False


def _validate_settings(values: dict[str, object], mode: str) -> None:
    for key in ("no_update_check", "validate_only", "verbose"):
        if not isinstance(values[key], bool):
            raise ValueError(f"{key} must be true or false")

    metadata = values["metadata_path"]
    if metadata is not None and not isinstance(metadata, str):
        raise ValueError("metadata_path must be a path string or null")

    rerun = values["rerun_mode"]
    if rerun not in _RERUN_MODES:
        raise ValueError(f"rerun_mode must be one of: {', '.join(_RERUN_MODES)}")

    if mode == "minidump" and rerun != "once":
        raise ValueError("--rerun-mode prompt/daemon requires live process mode")

    interval = values["poll_interval"]
    if (isinstance(interval, bool) or not isinstance(interval, (int, float))
            or not 0 < interval <= sys.float_info.max):
        raise ValueError("poll_interval must be a positive finite number")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
            description="Run from a live process or an offline minidump",
            argument_default=argparse.SUPPRESS,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {CURRENT_VERSION}")
    parser.add_argument("--minidump", help="Path to full-memory .dmp or .dmp.zst minidump (offline mode)")
    settings: dict[argparse.Action, object] = {
        parser.add_argument("--metadata-path", help="global-metadata.dat path override"): None,
        parser.add_argument("--no-update-check", action="store_true",
                            help="Skip the startup GitHub release check"): False,
        parser.add_argument("--rerun-mode", choices=_RERUN_MODES, help="Live rerun behavior"): "prompt",
        parser.add_argument("--poll-interval", type=float, help="Seconds between daemon extraction passes"): 2.0,
        parser.add_argument("--validate-only", action=argparse.BooleanOptionalAction,
                            help="Only validate registered classes and exit"): False,
        parser.add_argument("-v", "--verbose", action=argparse.BooleanOptionalAction,
                            help="Enable debug logging"): False,
    }
    parser.add_argument("--auto-metadata", dest="metadata_path", action="store_const", const=None,
                        help="Use automatic metadata discovery instead of the saved override")
    parser.add_argument("--update-check", dest="no_update_check", action="store_false",
                        help="Run the startup GitHub release check even if disabled in config")

    cli = vars(parser.parse_args(argv))
    minidump = cli.get("minidump")
    mode = "minidump" if minidump else "live"
    mode_settings = {
        "live": settings,
        "minidump": {action: default for action, default in settings.items() if action.dest not in _LIVE_ONLY},
    }

    path = _config_path()
    try:
        config = _read_config(path)
        changed = _backfill_config(config, mode_settings)
        section = config[mode]
        if not isinstance(section, dict):
            raise ValueError(f"{mode} must be a JSON object")

        values = {action.dest: default for action, default in settings.items()}
        if mode == "minidump":
            values["rerun_mode"] = "once"

        values.update({action.dest: section[action.dest] for action in mode_settings[mode]})
        values.update(cli)
        _validate_settings(values, mode)
        if "metadata_path" not in cli and (saved_path := values["metadata_path"]):
            assert isinstance(saved_path, str)
            values["metadata_path"] = str(path.parent / saved_path)
    except (OSError, ValueError) as exc:
        parser.error(f"{path} ({mode}): {exc}")

    if changed:
        try:
            _write_config(path, config)
        except (OSError, UnicodeError) as exc:
            print(f"WARNING: Could not save config {path}: {exc}", file=sys.stderr)

    values["minidump"] = minidump
    return argparse.Namespace(**values)
