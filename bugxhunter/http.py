"""Minimal HTTP client for the scanners.

The web and vulnerability scanners need something that can fetch a URL and
hand back a body, a status and the response headers. The Android app has
this in Java as ``core/Fetcher``; this is the same contract in Python so
the two agree on what "the request failed" means.

Pure stdlib on purpose: the server has to run on a bare Termux install
without pulling in requests.
"""

import gzip
import io
import socket
import ssl
import time
import urllib.error
import urllib.request
import zlib
from dataclasses import dataclass, field
from typing import List, Optional

DEFAULT_UA = ("Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36")

MAX_BODY = 2 * 1024 * 1024


@dataclass
class Response:
    """A fetched URL.

    ``ok`` is False for anything that did not produce a response body:
    DNS failure, refused connection, timeout, TLS error. A 403 is ok=True
    with status=403, because the server did answer.
    """

    url: str
    status: int = 0
    body: str = ""
    headers: List[str] = field(default_factory=list)
    err: str = ""
    elapsed_ms: float = 0.0

    @property
    def ok(self) -> bool:
        return self.status > 0 and not self.err

    def header(self, name: str) -> Optional[str]:
        """Case-insensitive single header lookup."""
        wanted = name.lower()
        for raw in self.headers:
            if ":" not in raw:
                continue
            key, _, value = raw.partition(":")
            if key.strip().lower() == wanted:
                return value.strip()
        return None


class Fetcher:
    """HTTP client with a real timeout and a body cap."""

    def __init__(self, timeout=8.0, user_agent=DEFAULT_UA, max_body=MAX_BODY,
                 follow_redirects=True, max_redirects=5, verify_tls=False,
                 headers=None):
        self.timeout = timeout
        self.user_agent = user_agent
        self.max_body = max_body
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects
        self.verify_tls = verify_tls
        self.extra_headers = dict(headers or {})

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _build_opener(self):
        handlers = []
        if not self.verify_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        if not self.follow_redirects:
            handlers.append(_NoRedirect())
        opener = urllib.request.build_opener(*handlers)
        # No redirect handler when following is on, so urllib's default
        # redirect handling applies.
        if self.follow_redirects:
            opener = urllib.request.build_opener()
            if not self.verify_tls:
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=ctx))
        return opener

    def _decode(self, raw: bytes, encoding: str) -> str:
        if encoding == "gzip":
            try:
                raw = gzip.decompress(raw)
            except OSError:
                try:
                    raw = zlib.decompress(raw, 16 + zlib.MAX_WBITS)
                except zlib.error:
                    pass
        elif encoding == "deflate":
            try:
                raw = zlib.decompress(raw)
            except zlib.error:
                try:
                    raw = zlib.decompress(raw, -zlib.MAX_WBITS)
                except zlib.error:
                    pass
        return raw.decode("utf-8", errors="replace")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def get(self, url: str, headers=None) -> Response:
        """Fetch *url*. Never raises; failures come back as ok=False."""
        started = time.time()
        req_headers = {
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        }
        req_headers.update(self.extra_headers)
        req_headers.update(headers or {})

        try:
            req = urllib.request.Request(url, headers=req_headers,
                                         method="GET")
            opener = self._build_opener()
            with opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read(self.max_body + 1)
                truncated = len(raw) > self.max_body
                if truncated:
                    raw = raw[:self.max_body]
                encoding = (resp.headers.get("Content-Encoding") or "").lower()
                body = self._decode(raw, encoding)
                header_list = ["{}: {}".format(k, v) for k, v in resp.headers.items()]
                return Response(
                    url=url,
                    status=resp.status,
                    body=body,
                    headers=header_list,
                    elapsed_ms=(time.time() - started) * 1000,
                )
        except urllib.error.HTTPError as exc:
            # The server answered, just not with 2xx. That is still a
            # response, and the body often carries the interesting bit.
            try:
                raw = exc.read(self.max_body)
                body = raw.decode("utf-8", errors="replace")
            except Exception:
                body = ""
            header_list = ["{}: {}".format(k, v) for k, v in exc.headers.items()] \
                if exc.headers else []
            return Response(
                url=url,
                status=exc.code,
                body=body,
                headers=header_list,
                elapsed_ms=(time.time() - started) * 1000,
            )
        except urllib.error.URLError as exc:
            return Response(url=url, err=str(exc.reason),
                            elapsed_ms=(time.time() - started) * 1000)
        except socket.timeout:
            return Response(url=url, err="timeout after {}s".format(self.timeout),
                            elapsed_ms=(time.time() - started) * 1000)
        except (ssl.SSLError, ConnectionError, OSError, ValueError) as exc:
            return Response(url=url, err=str(exc),
                            elapsed_ms=(time.time() - started) * 1000)

    def head(self, url: str) -> Response:
        """HEAD request. Returns the same shape as get()."""
        try:
            req = urllib.request.Request(url, method="HEAD",
                                         headers={"User-Agent": self.user_agent})
            opener = self._build_opener()
            with opener.open(req, timeout=self.timeout) as resp:
                header_list = ["{}: {}".format(k, v) for k, v in resp.headers.items()]
                return Response(url=url, status=resp.status, headers=header_list)
        except urllib.error.HTTPError as exc:
            return Response(url=url, status=exc.code)
        except Exception as exc:
            return Response(url=url, err=str(exc))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Turn redirects into errors so the caller can see the Location."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
