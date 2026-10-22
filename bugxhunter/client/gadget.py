"""Rootless instrumentation: patch an APK to carry Frida Gadget.

frida-server cannot run without root, because it injects by ptracing a
process it does not own, and Android has restricted ptrace to a
process's own descendants since Android 9. There is no way around that
requirement, and anyone claiming otherwise is shipping something that
does not work.

What does work without root is Frida Gadget. It is a shared library that
loads inside the target process, so it needs no privilege the app does
not already have. The app is instrumented by rebuilding it with the
gadget linked in.

The cost is that the APK is re-signed, so its signature changes. An
app that checks its own signature, or that talks to a backend with
signature-based pinning, will notice. That is a property of the
technique, not a bug in the tooling, and it is why this is suited to
testing builds you control.

The pipeline:

    apktool d   decode the APK
    inject     add lib/<abi>/libfrida-gadget.so and the config
    apktool b   rebuild
    zipalign   align for the target ABI
    sign        v2/v3 with apksigner, v1 with jarsigner as a fallback
    adb install install it
"""

import json
import lzma
import os
import shutil
import subprocess
import tempfile
import urllib.request
from typing import Dict, List, Optional

# Frida's Android gadget is published per ABI, and the release names
# are not the Android ABI names: "arm64", not "arm64-v8a".
ABIS = ("arm64", "arm", "x86_64", "x86")

# The release assets are xz compressed.
GADGET_SUFFIX = ".so.xz"

DEFAULT_GADGET_PORT = 27042
GADGET_LIBRARY = "libfrida-gadget.so"
GADGET_CONFIG_NAME = "libfrida-gadget.config.json"

RELEASES = "https://api.github.com/repos/frida/frida/releases/tags"


class GadgetError(RuntimeError):
    """A step of the pipeline failed. The message says why."""


def _run(argv, timeout=300, cwd=None, env=None):
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout,
            cwd=cwd, env=env)
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        raise GadgetError("{} is not installed".format(argv[0]))
    except subprocess.TimeoutExpired:
        raise GadgetError("{} timed out after {}s".format(argv[0], timeout))


class GadgetTool:
    """Build an instrumented APK that Frida can talk to without root."""

    def __init__(self, workdir: str = None, timeout: int = 300,
                 aapt: str = None):
        self.workdir = workdir or tempfile.mkdtemp(prefix="xbug-gadget-")
        self.timeout = timeout
        self.keystore = os.path.join(self.workdir, "debug.keystore")
        # apktool ships an x86_64 aapt2, which cannot run on an arm
        # device. An explicit aapt2 is passed through so the pipeline
        # works on whatever architecture the operator is on.
        self.aapt = aapt

    # ------------------------------------------------------------------
    # Host requirements
    # ------------------------------------------------------------------
    def check_tools(self) -> Dict[str, dict]:
        """Report which host tools are present and which are missing.

        Each entry says whether the tool is required, and what it is
        used for, so a missing tool is actionable rather than a guess.
        """
        wanted = [
            ("apktool", True, "decode and rebuild the APK"),
            ("aapt2", False, "apktool's own aapt2 is x86_64; pass --aapt on an arm host"),
            ("apksigner", False, "sign with a v2/v3 signature"),
            ("jarsigner", False, "sign with a v1 signature, as a fallback"),
            ("keytool", False, "create the debug keystore"),
            ("zipalign", False, "align the APK for the target ABI"),
            ("adb", False, "install the APK"),
        ]
        report = {}
        for name, required, purpose in wanted:
            path = shutil.which(name)
            report[name] = {
                "present": path is not None,
                "required": required,
                "purpose": purpose,
                "path": path or "",
            }
        return report

    def missing_required(self) -> List[str]:
        report = self.check_tools()
        return [name for name, meta in report.items()
                if meta["required"] and not meta["present"]]

    # ------------------------------------------------------------------
    # Gadget binary
    # ------------------------------------------------------------------
    @staticmethod
    def gadget_url(version: str, abi: str) -> str:
        return ("https://github.com/frida/frida/releases/download/"
                "{v}/frida-gadget-{v}-android-{abi}.so.xz").format(v=version, abi=abi)

    def fetch_gadget(self, version: str, abi: str) -> str:
        """Download the gadget for an ABI and return the path to the .so.

        The release asset is xz compressed, so it is decompressed on the
        way in. The APK needs the raw library.
        """
        if abi not in ABIS:
            raise GadgetError("unsupported ABI: {}".format(abi))
        dest = os.path.join(self.workdir, "{}-{}".format(abi, GADGET_LIBRARY))
        if os.path.isfile(dest):
            return dest

        url = self.gadget_url(version, abi)
        try:
            with urllib.request.urlopen(url, timeout=180) as response:
                data = response.read()
        except Exception as exc:
            raise GadgetError("could not fetch the gadget from {}: {}".format(url, exc))
        if len(data) < 1024:
            raise GadgetError("the gadget download was too small to be a library")

        try:
            raw = lzma.decompress(data)
        except lzma.LZMAError as exc:
            raise GadgetError("the gadget download was not valid xz: {}".format(exc))
        if len(raw) < 1024:
            raise GadgetError("the decompressed gadget was too small to be a library")

        with open(dest, "wb") as handle:
            handle.write(raw)
        return dest

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------
    @staticmethod
    def gadget_config(port: int = DEFAULT_GADGET_PORT,
                      address: str = "127.0.0.1") -> dict:
        """The config Frida's gadget reads.

        Listen mode makes the app wait for a client, which is what an
        engagement wants: the operator attaches when ready rather than
        racing the app's start-up.
        """
        return {
            "interaction": {
                "type": "listen",
                "address": address,
                "port": port,
                "on_port_change": "reload",
            },
            "runtime": "qjs",
        }

    # ------------------------------------------------------------------
    # Signing
    # ------------------------------------------------------------------
    def ensure_keystore(self, password: str = "android") -> str:
        """Create the debug keystore if it is not there already."""
        if os.path.isfile(self.keystore):
            return self.keystore
        if not shutil.which("keytool"):
            raise GadgetError("keytool is needed to create the debug keystore")
        code, _, err = _run([
            "keytool", "-genkeypair", "-v",
            "-keystore", self.keystore,
            "-storepass", password, "-keypass", password,
            "-alias", "androiddebugkey",
            "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
            "-dname", "CN=Android Debug,O=Android,C=US",
        ], timeout=60)
        if code != 0:
            raise GadgetError("keytool failed: " + err.strip()[:300])
        return self.keystore

    def sign(self, apk: str, password: str = "android") -> dict:
        """Sign the APK, preferring a v2/v3 signature."""
        keystore = self.ensure_keystore(password)
        signed = apk[:-4] + "-signed.apk" if apk.endswith(".apk") else apk + "-signed.apk"

        if shutil.which("apksigner"):
            code, _, err = _run([
                "apksigner", "sign",
                "--ks", keystore, "--ks-pass", "pass:" + password,
                "--key-pass", "pass:" + password,
                "--ks-key-alias", "androiddebugkey",
                "--out", signed, apk,
            ], timeout=120)
            if code != 0:
                raise GadgetError("apksigner failed: " + err.strip()[:300])
            return {"signed": signed, "scheme": "v2/v3"}

        if shutil.which("jarsigner"):
            code, _, err = _run([
                "jarsigner", "-keystore", keystore, "-storepass", password,
                "-keypass", password, "-sigalg", "SHA256withRSA",
                "-digestalg", "SHA-256", "-signedjar", signed, apk,
            ], timeout=120)
            if code != 0:
                raise GadgetError("jarsigner failed: " + err.strip()[:300])
            return {
                "signed": signed,
                "scheme": "v1",
                "note": ("signed with jarsigner, which is a v1 signature. "
                         "Some devices and some apps will not accept it; "
                         "install apksigner for a v2/v3 signature."),
            }

        raise GadgetError("neither apksigner nor jarsigner is installed")

    # ------------------------------------------------------------------
    # The pipeline
    # ------------------------------------------------------------------
    def instrument(self, apk_path: str, abi: str = "arm64",
                   version: str = "17.24.3", port: int = DEFAULT_GADGET_PORT,
                   address: str = "127.0.0.1",
                   out_apk: str = None) -> dict:
        """Rebuild the APK with the gadget linked in and signed.

        Returns a dict describing every step, so a failure says which
        step failed rather than just that something did.
        """
        if not os.path.isfile(apk_path):
            raise GadgetError("no such APK: {}".format(apk_path))
        missing = self.missing_required()
        if missing:
            raise GadgetError("missing required tools: " + ", ".join(missing))

        steps = []

        decoded = os.path.join(self.workdir, "decoded")
        shutil.rmtree(decoded, ignore_errors=True)

        # 1. Decode.
        code, _, err = _run(["apktool", "d", apk_path, "-o", decoded],
                            timeout=self.timeout)
        if code != 0:
            raise GadgetError("apktool could not decode the APK: "
                              + err.strip()[:300])
        steps.append("decoded")

        # 2. The gadget library.
        gadget = self.fetch_gadget(version, abi)
        lib_dir = os.path.join(decoded, "lib", abi)
        os.makedirs(lib_dir, exist_ok=True)
        shutil.copyfile(gadget, os.path.join(lib_dir, GADGET_LIBRARY))
        steps.append("injected the gadget for {}".format(abi))

        # 3. The config, as an asset, and the manifest entry that points
        #    at it.
        assets = os.path.join(decoded, "assets")
        os.makedirs(assets, exist_ok=True)
        config = self.gadget_config(port=port, address=address)
        with open(os.path.join(assets, GADGET_CONFIG_NAME), "w",
                  encoding="utf-8") as handle:
            json.dump(config, handle, indent=2)
        self._patch_manifest(os.path.join(decoded, "AndroidManifest.xml"))
        steps.append("added the gadget config")

        # 4. Rebuild.
        rebuilt = out_apk or os.path.join(self.workdir, "gadget-unsigned.apk")
        build_args = ["apktool", "b", decoded, "-o", rebuilt]
        if self.aapt:
            build_args.extend(["--aapt", self.aapt])
        code, _, err = _run(build_args, timeout=self.timeout)
        if code != 0:
            raise GadgetError("apktool could not rebuild the APK: "
                              + err.strip()[:300])
        steps.append("rebuilt")

        # 5. Align, when the tool is there. An unaligned APK still
        #    installs, it just uses more space and loads slower.
        aligned = rebuilt
        if shutil.which("zipalign"):
            candidate = rebuilt[:-4] + "-aligned.apk"
            code, _, err = _run(["zipalign", "-p", "-f", "4", rebuilt, candidate],
                                timeout=120)
            if code == 0:
                aligned = candidate
                steps.append("aligned")

        # 6. Sign.
        signed = self.sign(aligned)
        steps.append("signed ({})".format(signed["scheme"]))

        return {
            "ok": True,
            "apk": signed["signed"],
            "abi": abi,
            "port": port,
            "address": address,
            "config": config,
            "steps": steps,
            "note": signed.get("note", ""),
        }

    @staticmethod
    def _patch_manifest(path: str) -> bool:
        """Point the manifest at the gadget config.

        The meta-data is what tells the gadget which asset holds its
        configuration. Without it the gadget starts with its defaults,
        which listen on a random port.
        """
        if not os.path.isfile(path):
            return False
        body = open(path, encoding="utf-8").read()
        if "frida_gadget_config" in body:
            return True

        marker = '<meta-data android:name="frida_gadget_config" '
        marker += 'android:value="{}"/>'.format(GADGET_CONFIG_NAME)

        # Insert into the <application> element, as its first child.
        at = body.find("<application")
        if at < 0:
            return False
        close = body.find(">", at)
        if close < 0:
            return False
        body = body[:close + 1] + marker + body[close + 1:]
        open(path, "w", encoding="utf-8").write(body)
        return True

    # ------------------------------------------------------------------
    # Installation
    # ------------------------------------------------------------------
    def install(self, apk: str, device: str = None) -> dict:
        """Install the instrumented APK with adb."""
        if not shutil.which("adb"):
            raise GadgetError("adb is needed to install the APK")
        argv = ["adb"]
        if device:
            argv.extend(["-s", device])
        argv.extend(["install", "-r", "-g", apk])
        code, out, err = _run(argv, timeout=300)
        if code != 0:
            raise GadgetError("adb install failed: "
                              + (err.strip() or out.strip())[:300])
        return {"ok": True, "output": out.strip()[:400]}

    def forward(self, port: int = DEFAULT_GADGET_PORT, device: str = None) -> dict:
        """Forward the gadget port to this machine.

        The gadget listens on the device, so the operator needs a path
        to it. Over adb that is a port forward; over a network it is the
        device's address.
        """
        if not shutil.which("adb"):
            raise GadgetError("adb is needed to forward the port")
        argv = ["adb"]
        if device:
            argv.extend(["-s", device])
        argv.extend(["forward", "tcp:{}".format(port), "tcp:{}".format(port)])
        code, out, err = _run(argv, timeout=60)
        if code != 0:
            raise GadgetError("adb forward failed: " + err.strip()[:300])
        return {"ok": True, "port": port, "output": out.strip()[:200]}
