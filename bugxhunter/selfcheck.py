"""Self-check: import every module and evaluate every annotation.

Python 3.14 evaluates annotations lazily, under PEP 649. A name that a
function annotation refers to but never imports therefore causes no
error at all on 3.14, and a hard NameError on 3.11, where annotations
are still evaluated eagerly. A module that imports cleanly on a new
phone can therefore fail to import on the server that runs it.

This module forces the annotations to be resolved, so that difference
shows up wherever the check is run rather than only in CI.
"""

import importlib
import inspect
import typing
from typing import Dict, List, Optional

MODULES = [
    "bugxhunter.config",
    "bugxhunter.steps",
    "bugxhunter.frida",
    "bugxhunter.posture",
    "bugxhunter.termux",
    "bugxhunter.vpn",
    "bugxhunter.http",
    "bugxhunter.tools",
    "bugxhunter.privileges",
    "bugxhunter.server",
    "bugxhunter.hooks",
    "bugxhunter.hooks.lint",
    "bugxhunter.client.smart",
    "bugxhunter.client.reverse_ssh",
    "bugxhunter.client.cli",
    "bugxhunter.client.drop",
    "bugxhunter.client.gadget",
    "bugxhunter.scanners.network",
    "bugxhunter.scanners.web",
    "bugxhunter.scanners.vuln",
    "bugxhunter.scanners.credential",
    "bugxhunter.scanners.config_audit",
]


def _resolve(obj, where, problems):
    """Force every annotation on a function or class to be resolved."""
    try:
        typing.get_type_hints(obj)
    except Exception as exc:
        problems.append("{}: {}: {}".format(where, type(exc).__name__, exc))
        return
    # get_type_hints covers the function and its members, but not
    # annotations on nested class attributes, so walk those too.
    for name, value in vars(obj).items() if isinstance(obj, type) else ():
        if isinstance(value, type):
            _resolve(value, "{}.{}".format(where, name), problems)


def check() -> Dict[str, object]:
    """Import every module and resolve every annotation."""
    problems: List[str] = []
    checked = 0

    for name in MODULES:
        try:
            module = importlib.import_module(name)
        except Exception as exc:
            problems.append("{}: import failed: {}: {}".format(
                name, type(exc).__name__, exc))
            continue

        for attr_name, attr in vars(module).items():
            if inspect.isfunction(attr) and attr.__module__ == name:
                checked += 1
                _resolve(attr, "{}.{}".format(name, attr_name), problems)
            elif inspect.isclass(attr) and attr.__module__ == name:
                checked += 1
                _resolve(attr, "{}.{}".format(name, attr_name), problems)
                for meth_name, meth in vars(attr).items():
                    if inspect.isfunction(meth):
                        checked += 1
                        _resolve(meth, "{}.{}.{}".format(
                            name, attr_name, meth_name), problems)

    return {
        "ok": not problems,
        "modules": len(MODULES),
        "checked": checked,
        "problems": problems,
    }


def main() -> int:
    result = check()
    if result["ok"]:
        print("ok: {modules} modules, {checked} annotations resolved".format(
            modules=result["modules"], checked=result["checked"]))
        return 0
    for problem in result["problems"]:
        print("FAIL " + problem)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
