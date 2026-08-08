"""A real HTTP origin on 127.0.0.1, for testing the collection layer offline.

kwara's analysis layer is well covered because it is pure functions over
strings. The collection layer is not, because every one of its code paths
begins with an outbound request: `scanner.scan_url` walks a redirect chain a
hop at a time, `cloaking._fetch_summary` fetches the same URL twice and
compares the bodies, `adstxt._fetch_ads_txt` reads a capped byte prefix,
`_snapshot_worker` drives a browser. Mocking `requests.get` tests the code's
handling of a dict we wrote ourselves; it cannot tell us whether the code
survives a 302 to a relative Location, a server that never answers, or a body
that differs by User-Agent. Those are exactly the behaviours the tool exists
to detect, so they have to be real.

Hence a real server, and one that can misbehave on demand:

    def test_something(site):
        site.route("/", status=302, headers={"Location": "/landing"})
        site.route("/landing", body=b"<html>...")
        resp = requests.get(site.url)

Bound to 127.0.0.1 with port 0 (the kernel picks a free port), one instance
per test, torn down in the fixture's finally block. Nothing leaves the loopback
interface and no test can collide with another over a fixed port.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, NamedTuple
from urllib.parse import parse_qs, urlsplit

import pytest

# ── Sample corpora ────────────────────────────────────────────────────────
# Paths, not preloaded blobs: some tests want the bytes to serve, others want
# the path to hand to a parser that reads from disk
# (fingerprints.extract_tracking_ids_from_file).
FIXTURES_DIR = Path(__file__).resolve().parent
PAGES_DIR = FIXTURES_DIR / "pages"
ADSTXT_DIR = FIXTURES_DIR / "adstxt"


def page_bytes(name: str) -> bytes:
    """Read `pages/<name>` — e.g. page_bytes("farm_static.html")."""
    return (PAGES_DIR / name).read_bytes()


def adstxt_bytes(name: str) -> bytes:
    """Read `adstxt/<name>` — e.g. adstxt_bytes("normal.txt")."""
    return (ADSTXT_DIR / name).read_bytes()


# ── Request records ───────────────────────────────────────────────────────

class _Headers(dict):
    """Request headers, looked up without caring about case.

    Worth the twenty lines: `requests` sends `User-Agent`, Chromium sends
    `user-agent`, and a test asserting on the scanner's UA should not have to
    know which client produced the request. Iteration still yields the keys as
    they arrived on the wire, so a test may assert on casing if it wants to.
    """

    def __getitem__(self, key: str) -> str:
        try:
            return dict.__getitem__(self, key)
        except KeyError:
            pass
        lowered = key.lower()
        for k, v in self.items():
            if k.lower() == lowered:
                return v
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, key: object) -> bool:
        if not isinstance(key, str):
            return False
        try:
            self[key]
        except KeyError:
            return False
        return True


class _Path(str):
    """The request path, carrying its query string as an attribute.

    `request.path == "/landing"` compares equal for `/landing?utm_source=fb`,
    because a test asking "was /landing hit?" should not have to reconstruct
    the query. A cloaking test asking the opposite question reads
    `request.query` or `request.params`.
    """

    def __new__(cls, path: str, query: str = "") -> "_Path":
        obj = super().__new__(cls, path)
        obj.query = query
        return obj

    @property
    def params(self) -> dict[str, list[str]]:
        return parse_qs(self.query, keep_blank_values=True)

    @property
    def full(self) -> str:
        return f"{self}?{self.query}" if self.query else str(self)


class Request(NamedTuple):
    """One received request, as `(method, path, headers)`.

    A three-tuple so `for method, path, headers in site.requests` works, with
    the query reachable through the path (see `_Path`) rather than as a fourth
    element that would break unpacking.
    """

    method: str
    path: _Path
    headers: _Headers

    @property
    def query(self) -> str:
        return self.path.query

    @property
    def params(self) -> dict[str, list[str]]:
        return self.path.params

    @property
    def full_path(self) -> str:
        return self.path.full

    @property
    def user_agent(self) -> str:
        return self.headers.get("User-Agent", "")


# ── Routes ────────────────────────────────────────────────────────────────

@dataclass
class _Route:
    status: int = 200
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    delay: float = 0.0
    fn: Callable[[Request], tuple] | None = None


def _as_bytes(body: Any) -> bytes:
    if body is None:
        return b""
    if isinstance(body, bytes):
        return body
    if isinstance(body, bytearray):
        return bytes(body)
    if isinstance(body, str):
        return body.encode("utf-8")
    raise TypeError(f"body must be bytes or str, got {type(body).__name__}")


def _normalise(path: str) -> str:
    """Route key: leading slash, query and fragment discarded.

    `site.route("/ads.txt")` therefore also answers `/ads.txt?v=2`; a route
    that needs to discriminate on the query is a `route_dynamic`.
    """
    path = urlsplit(path or "/").path or "/"
    return path if path.startswith("/") else "/" + path


class _Handler(BaseHTTPRequestHandler):
    # HTTP/1.1 with an explicit Content-Length on every response: requests'
    # stream=True + iter_content path (adstxt, lightweight_fetch, cloaking)
    # behaves differently against a connection-close server, and we want the
    # tests exercising the shape production actually meets.
    protocol_version = "HTTP/1.1"
    # Idle keep-alive sockets must not outlive the test that opened them.
    timeout = 15

    # ── plumbing ─────────────────────────────────────────────────────────
    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: D401
        """Silence the stderr access log — pytest output is not a web log."""

    @property
    def _site(self) -> "TestSite":
        return self.server.site  # type: ignore[attr-defined]

    def _record(self) -> Request:
        split = urlsplit(self.path)
        req = Request(
            method=self.command,
            path=_Path(split.path or "/", split.query),
            headers=_Headers(self.headers.items()),
        )
        self._site._record(req)
        return req

    def _drain_body(self) -> None:
        """Read and discard any request body so keep-alive stays in sync."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > 0:
            self.rfile.read(length)

    def _respond(self, status: int, headers: dict[str, str], body: bytes,
                 *, include_body: bool) -> None:
        merged = {"Server": "kwara-test-fixture", "Content-Type": "text/html; charset=utf-8"}
        # Route headers override the defaults case-insensitively, so a test
        # setting {"server": "cloudflare"} gets exactly one Server header —
        # header_analysis fingerprints on that key and would see "a, b" for a
        # duplicate.
        lowered = {k.lower() for k in headers}
        merged = {k: v for k, v in merged.items() if k.lower() not in lowered}
        merged.update(headers)

        no_body_status = status in (204, 304)
        if not no_body_status:
            merged["Content-Length"] = str(len(body))
        merged.setdefault("Date", self.date_time_string())

        self.send_response_only(status)
        for key, value in merged.items():
            self.send_header(key, value)
        self.end_headers()
        if include_body and body and not no_body_status:
            self.wfile.write(body)

    def _handle(self, *, include_body: bool = True) -> None:
        self._drain_body()
        req = self._record()
        route = self._site._route_for(req.path)

        if route is None:
            self._respond(404, {}, b"<html><body>404 not found</body></html>",
                          include_body=include_body)
            return

        if route.delay:
            time.sleep(route.delay)

        if route.fn is not None:
            try:
                result = route.fn(req)
            except Exception as exc:  # a broken route must not hang the client
                self._respond(500, {}, f"route_dynamic raised: {exc!r}".encode(),
                              include_body=include_body)
                return
            try:
                status, headers, body = result
            except (TypeError, ValueError):
                self._respond(
                    500, {},
                    b"route_dynamic must return (status, headers, body)",
                    include_body=include_body,
                )
                return
            self._respond(int(status), dict(headers or {}), _as_bytes(body),
                          include_body=include_body)
            return

        self._respond(route.status, dict(route.headers), route.body,
                      include_body=include_body)

    # ── verbs ────────────────────────────────────────────────────────────
    def do_GET(self) -> None:
        self._handle()

    def do_HEAD(self) -> None:
        self._handle(include_body=False)

    def do_POST(self) -> None:
        self._handle()

    def do_PUT(self) -> None:
        self._handle()

    def do_DELETE(self) -> None:
        self._handle()

    def do_OPTIONS(self) -> None:
        self._handle()


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    site: "TestSite"


class TestSite:
    """A throwaway HTTP origin. Started on construction, stopped by `close()`.

    Also usable directly (`with TestSite() as other:`) when a test needs a
    second host — a redirect that leaves the domain, or two landing domains
    sharing one tracking ID, which is the signal this tool is built around.
    """

    __test__ = False  # not a pytest test class, despite the name

    def __init__(self, host: str = "127.0.0.1") -> None:
        self._routes: dict[str, _Route] = {}
        self._requests: list[Request] = []
        self._lock = threading.Lock()

        self._server = _Server((host, 0), _Handler)
        self._server.site = self
        self._host, self._port = self._server.server_address[:2]
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            kwargs={"poll_interval": 0.05},
            name=f"kwara-test-site:{self._port}",
            daemon=True,
        )
        self._thread.start()

    # ── public API ───────────────────────────────────────────────────────
    @property
    def url(self) -> str:
        """Origin with no trailing slash, e.g. `http://127.0.0.1:54321`."""
        return f"http://{self._host}:{self._port}"

    def url_for(self, path: str) -> str:
        """Absolute URL for `path`, query string preserved."""
        if not path:
            path = "/"
        if not path.startswith("/"):
            path = "/" + path
        return self.url + path

    def route(self, path: str, *, status: int = 200, body: Any = b"",
              headers: dict[str, str] | None = None, delay: float = 0.0) -> None:
        """Serve a fixed response at `path`.

        `body` takes bytes or str (encoded utf-8). `headers` overrides the
        defaults, Content-Type included. `delay` sleeps before the status line
        goes out, which is what makes the client raise a read timeout.
        """
        self._routes[_normalise(path)] = _Route(
            status=status,
            body=_as_bytes(body),
            headers=dict(headers or {}),
            delay=float(delay),
        )

    def route_dynamic(self, path: str,
                      fn: Callable[[Request], tuple]) -> None:
        """Serve a computed response: `fn(request) -> (status, headers, body)`.

        The request carries `.query`, `.params` and `.user_agent`, which is
        everything a cloaker discriminates on in practice.
        """
        self._routes[_normalise(path)] = _Route(fn=fn)

    @property
    def requests(self) -> list[Request]:
        """Every request received so far, in arrival order.

        A snapshot copy: iterating it while a background browser is still
        fetching subresources would otherwise mutate under the loop.
        """
        with self._lock:
            return list(self._requests)

    # ── lifecycle ────────────────────────────────────────────────────────
    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    def __enter__(self) -> "TestSite":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ── internals used by the handler ────────────────────────────────────
    def _record(self, req: Request) -> None:
        with self._lock:
            self._requests.append(req)

    def _route_for(self, path: str) -> _Route | None:
        return self._routes.get(_normalise(path))


@pytest.fixture
def site():
    """A local HTTP origin, one per test, always torn down.

    The teardown is in a finally block on purpose: a test that fails
    mid-assertion still has to give its port and its thread back, or a failing
    run leaves the suite leaking servers.
    """
    server = TestSite()
    try:
        yield server
    finally:
        server.close()
