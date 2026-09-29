#!/usr/bin/env python3
"""Generate version header from git tag or commit hash."""
import subprocess
import os
import sys

try:
    # PlatformIO exposes the build environment to extra scripts.
    Import("env")
    PROJECT_DIR = env.subst("$PROJECT_DIR")
except NameError:
    # Keep the script runnable directly for local checks.
    PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))

def get_version():
    """Get version from git tag or abbreviated commit hash."""
    # CI provides the ref explicitly. This is more reliable than asking git
    # to discover a tag in a shallow checkout, where tag metadata may be absent.
    build_version = os.environ.get("BUILD_VERSION")
    if build_version:
        if os.environ.get("GITHUB_REF_TYPE") == "tag":
            return build_version.removeprefix("v")
        if len(build_version) >= 8 and all(c in "0123456789abcdefABCDEF" for c in build_version):
            return build_version[:8]
        return build_version

    try:
        # Try to get the current tag
        tag = subprocess.check_output(
            ['git', 'describe', '--tags', '--exact-match'],
            stderr=subprocess.DEVNULL,
            cwd=PROJECT_DIR
        ).decode().strip()
        return tag
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    try:
        # Fall back to abbreviated commit hash
        commit = subprocess.check_output(
            ['git', 'rev-parse', '--short=8', 'HEAD'],
            stderr=subprocess.DEVNULL,
            cwd=PROJECT_DIR
        ).decode().strip()
        return commit
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    # Fallback if git is not available
    return "unknown"

def generate_header():
    """Generate the version header file."""
    version = get_version()
    header_content = f'''#ifndef VERSION_H
#define VERSION_H

#define FIRMWARE_VERSION "{version}"

#endif // VERSION_H
'''

    header_path = os.path.join(PROJECT_DIR, 'include', 'version.h')
    os.makedirs(os.path.dirname(header_path), exist_ok=True)

    with open(header_path, 'w') as f:
        f.write(header_content)

    print(f"Generated version.h with version: {version}")

# PlatformIO loads this file as a pre-build extra script.  Extra scripts are
# executed by PlatformIO rather than necessarily as a normal Python entry
# point, so invoke the generator at module load time.
generate_header()
