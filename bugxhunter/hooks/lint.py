"""Static checks for the Frida hook library.

The hooks cannot be exercised without a device and a live app, which
makes it easy to ship a script that never installs a single hook. These
checks catch the failure modes that would otherwise only show up on a
target:

* a syntax error, caught with node --check
* a hook installed on a dispatcher rather than a specific overload,
  which throws at runtime
* a replacement calling the very method it replaces, which recurses
* the same method hooked twice in one file, which nests the
  replacements and recurses
* a hook with no Purpose or Run line in its header

The point is that a hook that fails to install says so, loudly, rather
than running and quietly doing nothing.
"""

import os
import re
import shutil
import subprocess
from typing import Dict, List

# A hook that replaces a method should reach the original through the
# saved overload, so "this.method(" must not appear for a method that
# the same file also hooks.
DISPATCH_CALL = re.compile(r"\bthis\.(\w+)\s*\(")

# "X.method.overload(...)" assigned straight to .implementation means the
# hook is on a dispatcher, which throws when the method is overloaded.
DIRECT_IMPL = re.compile(
    r"(?m)^\s*[\w.$]+\.(\w+)\.overload\([^)]*\)\s*\.\s*implementation\s*=")
DIRECT_IMPL_MULTILINE = re.compile(
    r"(?m)^\s*[\w.$]+\.(\w+)\.overload\([^)]*\)\s*\n\s*\.implementation\s*=")

# "var x = X.method.overload(...)" is the good pattern.
SAVED_OVERLOAD = re.compile(
    r"(?m)^\s*var\s+(\w+)\s*=\s*[\w.$]+\.(\w+)\.overload\(")

OVERLOAD_CALL = re.compile(r"\.overload\(")

# Messages a hook can end with to show it got as far as installing.
COMPLETION_MARKERS = (
    "hooks installed",
    "methods",
    "=== ",            # discover_overloads prints a class banner
)


class LintResult:
    def __init__(self, name):
        self.name = name
        self.errors = []
        self.warnings = []

    @property
    def ok(self):
        return not self.errors

    def as_dict(self):
        return {
            "name": self.name,
            "ok": self.ok,
            "errors": self.errors,
            "warnings": self.warnings,
        }


def _syntax_check(path: str) -> List[str]:
    """Parse the file with node, if node is available."""
    node = shutil.which("node")
    if not node:
        return []
    try:
        proc = subprocess.run([node, "--check", path],
                              capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        return ["could not run node --check: {}".format(exc)]
    if proc.returncode == 0:
        return []
    return [proc.stderr.strip()[:500] or "syntax error"]


def lint_file(path: str) -> LintResult:
    """Check one hook file."""
    name = os.path.basename(path)
    result = LintResult(name)

    try:
        with open(path, "r", encoding="utf-8") as handle:
            source = handle.read()
    except OSError as exc:
        result.errors.append("cannot read: {}".format(exc))
        return result

    # 1. Syntax.
    for problem in _syntax_check(path):
        result.errors.append("syntax: " + problem)

    # 2. Header. A hook has to say what it does and how to run it.
    if "Purpose:" not in source:
        result.errors.append("header has no Purpose: line")
    if not re.search(r"(?m)^\s*\*\s*(Run|Usage):", source):
        result.errors.append("header has no Run: or Usage: line")

    # 3. Hooks installed on a dispatcher rather than a named overload.
    for match in DIRECT_IMPL.finditer(source):
        result.errors.append(
            "hook on {}.implementation is set straight off a dispatcher; "
            "save the overload first, e.g. "
            "var original = X.{}.overload(...); original.implementation = ..."
            .format(match.group(1), match.group(1)))
    for match in DIRECT_IMPL_MULTILINE.finditer(source):
        result.errors.append(
            "hook on {}.implementation is set straight off a dispatcher; "
            "save the overload first".format(match.group(1)))

    # 4. The same method hooked twice in one file.
    hooked = set()
    for match in SAVED_OVERLOAD.finditer(source):
        hooked.add(match.group(2))
    seen = set()
    for match in re.finditer(r"\.overload\(", source):
        pass
    for match in re.finditer(
            r"(?m)^\s*var\s+(\w+)\s*=\s*([\w.$]+)\.(\w+)\.overload\(", source):
        var_name, holder, method = match.groups()
        key = (holder, method)
        if key in seen:
            result.errors.append(
                "{} is hooked twice in this file; the second replacement "
                "calls the first, which recurses".format(method))
        seen.add(key)

    # 5. A replacement calling the method it replaces.
    for match in DISPATCH_CALL.finditer(source):
        name_called = match.group(1)
        if name_called in hooked:
            result.errors.append(
                "this.{}( is called but {} is hooked in this file; "
                "call the saved overload instead".format(name_called, name_called))

    # 6. Every hook should say what it hooked, so a partial install is
    #    visible in the output.
    if not any(marker in source for marker in COMPLETION_MARKERS):
        result.warnings.append(
            "no completion message, so a partial install is invisible")

    return result


def lint_directory(directory: str = None) -> List[LintResult]:
    """Check every hook in the library."""
    from . import HOOK_DIR
    directory = directory or HOOK_DIR
    results = []
    if not os.path.isdir(directory):
        return results
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".js"):
            continue
        results.append(lint_file(os.path.join(directory, name)))
    return results
