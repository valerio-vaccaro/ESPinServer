#!/usr/bin/env python3
"""Generate version header from git tag or commit hash."""
import subprocess
import os
import sys

def get_version():
    """Get version from git tag or abbreviated commit hash."""
    try:
        # Try to get the current tag
        tag = subprocess.check_output(
            ['git', 'describe', '--tags', '--exact-match'],
            stderr=subprocess.DEVNULL,
            cwd=os.path.dirname(__file__)
        ).decode().strip()
        return tag
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    try:
        # Fall back to abbreviated commit hash
        commit = subprocess.check_output(
            ['git', 'rev-parse', '--short=8', 'HEAD'],
            stderr=subprocess.DEVNULL,
            cwd=os.path.dirname(__file__)
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

    header_path = os.path.join(os.path.dirname(__file__), 'include', 'version.h')
    os.makedirs(os.path.dirname(header_path), exist_ok=True)

    with open(header_path, 'w') as f:
        f.write(header_content)

    print(f"Generated version.h with version: {version}")

if __name__ == '__main__':
    generate_header()
