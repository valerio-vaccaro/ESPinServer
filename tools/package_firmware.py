#!/usr/bin/env python3
"""Package PlatformIO builds for the ESP32 DIY flasher.

The output deliberately uses the filenames understood by esptool-js and by
the DIY flasher: the address is part of every binary filename, while
``index.json`` describes the files for each PlatformIO environment.
"""

import argparse
import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path


FLASH_FILES = (
    (0x1000, "bootloader.bin"),
    (0x8000, "partitions.bin"),
    (0xE000, "boot_app0.bin"),
    (0x10000, "firmware.bin"),
)


def boot_app0_source() -> Path | None:
    """Locate the Arduino-ESP32 boot app image installed by PlatformIO."""
    candidates = [
        Path.home() / ".platformio/packages/framework-arduinoespressif32/tools/partitions/boot_app0.bin",
        Path.home() / ".platformio/packages/framework-arduinoespressif32-libs/tools/partitions/boot_app0.bin",
    ]
    return next((candidate for candidate in candidates if candidate.exists()), None)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", type=Path, default=Path(".pio/build"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--base-url", default=".")
    args = parser.parse_args()

    output = args.output
    output.mkdir(parents=True, exist_ok=True)
    builds = []
    boot_app0 = boot_app0_source()

    for environment in sorted(path for path in args.build_dir.iterdir() if path.is_dir()):
        board_output = output / environment.name
        board_output.mkdir(parents=True, exist_ok=True)
        files = []
        for address, source_name in FLASH_FILES:
            source = environment / source_name
            if source_name == "boot_app0.bin" and not source.exists() and boot_app0:
                source = boot_app0
            if not source.exists():
                raise FileNotFoundError(f"{source} is required for {environment.name}")

            target_name = f"0x{address:04X}_{source_name}"
            target = board_output / target_name
            shutil.copyfile(source, target)
            files.append({
                "address": f"0x{address:X}",
                "file": f"{environment.name}/{target_name}",
                "sha256": sha256(target),
                "size": target.stat().st_size,
            })

        builds.append({
            "name": environment.name,
            "platformio_environment": environment.name,
            "files": files,
            # Aliases used by flasher implementations which call this field
            # flashFiles (the canonical files array remains above).
            "flashFiles": files,
        })

    manifest = {
        "name": "ESPinServer",
        "version": args.version,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "base_url": args.base_url,
        "builds": builds,
        "versions": [{"version": args.version, "builds": builds}],
    }
    (output / "index.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
