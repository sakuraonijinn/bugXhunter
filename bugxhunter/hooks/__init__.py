"""Frida hook library.

The scripts live in this directory as plain .js files. They are listed,
hashed and served by the server, and run by the client.

Every hook carries a SHA-256, and the library has a version of its own
that is the hash of all the individual hashes. A finding can therefore
cite exactly which script produced it, and that script is pinned to a
content hash rather than to a URL that might change underneath.

Gists would be the wrong home for this. A gist is mutable and has no
history, so "the script was in a gist" is not evidence of what ran
against a target. A commit SHA and a content hash are.
"""

import hashlib
import os
import re
import subprocess
from typing import Dict, List, Optional

HOOK_DIR = os.path.dirname(os.path.abspath(__file__))


def _parse_description(text: str) -> str:
    """Pull the Purpose line out of a hook's header comment."""
    for line in text.splitlines()[:40]:
        stripped = line.strip()
        if stripped.lower().startswith("* purpose:"):
            return stripped.split(":", 1)[1].strip()
    return ""


def _parse_run_command(text: str) -> str:
    """Pull the Run line out of a hook's header comment."""
    for line in text.splitlines()[:40]:
        stripped = line.strip()
        if stripped.lower().startswith("* run:"):
            return stripped.split(":", 1)[1].strip()
    return ""


class HookLibrary:
    """The set of Frida scripts shipped with the server."""

    def __init__(self, directory: str = None):
        self.directory = directory or HOOK_DIR
        self._cache: Dict[str, dict] = {}

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------
    def _load(self) -> Dict[str, dict]:
        if self._cache:
            return self._cache
        if not os.path.isdir(self.directory):
            return self._cache
        for name in sorted(os.listdir(self.directory)):
            if not name.endswith(".js"):
                continue
            path = os.path.join(self.directory, name)
            try:
                with open(path, "rb") as handle:
                    raw = handle.read()
            except OSError:
                continue
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                text = raw.decode("utf-8", "replace")
            self._cache[name] = {
                "name": name,
                "stem": name[:-3],
                "path": path,
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "description": _parse_description(text),
                "run": _parse_run_command(text),
            }
        return self._cache

    def list(self) -> List[dict]:
        """Every hook, with its hash and description."""
        return [dict(meta) for meta in self._load().values()]

    def names(self) -> List[str]:
        return list(self._load().keys())

    def get(self, name: str) -> Optional[dict]:
        """Metadata for one hook, by file name or stem."""
        hooks = self._load()
        if name in hooks:
            return dict(hooks[name])
        for meta in hooks.values():
            if meta["stem"] == name:
                return dict(meta)
        return None

    def read(self, name: str) -> Optional[str]:
        """The script text for one hook."""
        meta = self.get(name)
        if not meta:
            return None
        try:
            with open(meta["path"], "r", encoding="utf-8") as handle:
                return handle.read()
        except OSError:
            return None

    def path_for(self, name: str) -> Optional[str]:
        meta = self.get(name)
        return meta["path"] if meta else None

    # ------------------------------------------------------------------
    # Versioning
    # ------------------------------------------------------------------
    def version(self) -> str:
        """A version for the whole library.

        The hash of the sorted (name, sha256) pairs, so it changes if
        and only if a hook changes. Independent of git, so it works on
        a tarball or a device with no .git directory.
        """
        hooks = self._load()
        digest = hashlib.sha256()
        for name in sorted(hooks):
            digest.update(name.encode("utf-8"))
            digest.update(hooks[name]["sha256"].encode("ascii"))
        return digest.hexdigest()

    def git_commit(self) -> Optional[str]:
        """The commit the library is pinned to, if git can tell us."""
        root = os.path.dirname(os.path.dirname(self.directory))
        try:
            out = subprocess.run(
                ["git", "-C", root, "rev-parse", "HEAD"],
                capture_output=True, text=True, timeout=5,
            )
            if out.returncode == 0 and out.stdout.strip():
                return out.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass
        return None

    def manifest(self) -> dict:
        """The full library description, for publishing."""
        return {
            "version": self.version(),
            "git_commit": self.git_commit(),
            "count": len(self._load()),
            "hooks": self.list(),
        }
