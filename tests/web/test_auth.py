# SPDX-License-Identifier: AGPL-3.0-only
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from tests.web.conftest import ADMIN_PASSWORD, ADMIN_USER, csrf_from, login
from threatcull.store import users
from threatcull.store.users import set_password
from threatcull.web.app import create_app
from threatcull.web.deps import check_csrf, open_db
from threatcull.web.routes import auth
from threatcull.web.security import LoginRateLimiter

GENERIC_FAILURE = "Wrong username or password"


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _post_login(client: TestClient, password: str, *, username: str = ADMIN_USER) -> int:
    token = csrf_from(client.get("/login").text)
    response = client.post(
        "/login",
        data={"username": username, "password": password, "csrf": token},
        follow_redirects=False,
    )
    status: int = response.status_code
    return status


# --- login page -----------------------------------------------------------------


def test_login_page_renders_a_form_with_a_csrf_token(client: TestClient) -> None:
    response = client.get("/login")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert '<form method="post" action="/login">' in response.text
    assert len(csrf_from(response.text)) >= 32
    assert 'href="/static/app.css"' in response.text
    assert "<script" not in response.text


def test_login_page_keeps_the_same_csrf_token_within_a_session(client: TestClient) -> None:
    assert csrf_from(client.get("/login").text) == csrf_from(client.get("/login").text)


def test_static_css_is_served_without_login(client: TestClient) -> None:
    response = client.get("/static/app.css")
    assert response.status_code == 200
    assert "prefers-color-scheme" in response.text


def test_html_pages_carry_security_headers(client: TestClient) -> None:
    response = client.get("/login")
    assert response.headers["Content-Security-Policy"].startswith("default-src 'self'")
    assert response.headers["X-Frame-Options"] == "DENY"


# --- login / logout -------------------------------------------------------------


def test_login_success_sets_a_strict_httponly_cookie_and_redirects(
    client: TestClient, admin: str
) -> None:
    token = csrf_from(client.get("/login").text)
    response = client.post(
        "/login",
        data={"username": admin, "password": ADMIN_PASSWORD, "csrf": token},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    cookie = response.headers["set-cookie"].lower()
    assert cookie.startswith("threatcull_session=")
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    assert "max-age=43200" in cookie
    assert "secure" not in cookie  # plain HTTP on a LAN IP is the default
    home = client.get("/", follow_redirects=False)
    assert home.status_code == 200
    assert admin in home.text


def test_login_rotates_the_csrf_token(client: TestClient, admin: str) -> None:
    before = csrf_from(client.get("/login").text)
    after = login(client)
    assert after != before


@pytest.mark.parametrize(
    ("username", "password"),
    [(ADMIN_USER, "wrong password!!"), ("nobody", ADMIN_PASSWORD), ("", "")],
)
def test_login_failure_is_generic_401(
    client: TestClient, admin: str, username: str, password: str
) -> None:
    token = csrf_from(client.get("/login").text)
    response = client.post(
        "/login",
        data={"username": username, "password": password, "csrf": token},
        follow_redirects=False,
    )
    assert response.status_code == 401
    assert GENERIC_FAILURE in response.text
    assert client.get("/", follow_redirects=False).status_code == 303


def test_login_failure_does_not_echo_the_password(client: TestClient, admin: str) -> None:
    token = csrf_from(client.get("/login").text)
    response = client.post(
        "/login",
        data={"username": admin, "password": "hunter2-secret-guess", "csrf": token},
    )
    assert "hunter2-secret-guess" not in response.text


def test_login_escapes_the_echoed_username(client: TestClient) -> None:
    token = csrf_from(client.get("/login").text)
    response = client.post(
        "/login", data={"username": "<b>x</b>", "password": "whatever-long", "csrf": token}
    )
    assert "<b>x</b>" not in response.text
    assert "&lt;b&gt;x&lt;/b&gt;" in response.text


def test_login_without_csrf_is_403(client: TestClient, admin: str) -> None:
    client.get("/login")
    response = client.post(
        "/login", data={"username": admin, "password": ADMIN_PASSWORD}, follow_redirects=False
    )
    assert response.status_code == 403
    assert client.get("/", follow_redirects=False).status_code == 303


def test_login_with_a_csrf_token_from_another_session_is_403(
    client: TestClient, admin: str
) -> None:
    other_token = csrf_from(client.get("/login").text)
    with TestClient(client.app) as other:
        other.get("/login")
        response = other.post(
            "/login",
            data={"username": admin, "password": ADMIN_PASSWORD, "csrf": other_token},
            follow_redirects=False,
        )
        assert response.status_code == 403
        assert other.get("/", follow_redirects=False).status_code == 303


def test_login_with_no_session_at_all_is_403(client: TestClient, admin: str) -> None:
    response = client.post(
        "/login",
        data={"username": admin, "password": ADMIN_PASSWORD, "csrf": "made-up"},
        follow_redirects=False,
    )
    assert response.status_code == 403


def test_logout_without_csrf_is_403_and_keeps_the_session(
    client: TestClient, logged_in: str
) -> None:
    response = client.post("/logout", follow_redirects=False)
    assert response.status_code == 403
    assert client.get("/", follow_redirects=False).status_code == 200


def test_logout_with_a_stale_csrf_token_is_403(client: TestClient, admin: str) -> None:
    pre_login_token = csrf_from(client.get("/login").text)
    login(client)
    response = client.post("/logout", data={"csrf": pre_login_token}, follow_redirects=False)
    assert response.status_code == 403
    assert client.get("/", follow_redirects=False).status_code == 200


def test_logout_clears_the_session(client: TestClient, logged_in: str) -> None:
    response = client.post("/logout", data={"csrf": logged_in}, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert client.get("/", follow_redirects=False).status_code == 303
    assert client.get("/api/v1/me").status_code == 401


# --- protected routes -----------------------------------------------------------


def test_protected_page_redirects_to_login_when_logged_out(client: TestClient) -> None:
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert response.headers["X-Frame-Options"] == "DENY"


def test_api_is_401_json_when_logged_out(client: TestClient) -> None:
    response = client.get("/api/v1/me")
    assert response.status_code == 401
    assert response.json() == {"detail": "authentication required"}


def test_api_me_returns_the_logged_in_user(client: TestClient, logged_in: str) -> None:
    response = client.get("/api/v1/me")
    assert response.status_code == 200
    assert response.json() == {"username": ADMIN_USER}


def test_check_csrf_accepts_the_x_csrf_token_header(tmp_path: Path) -> None:
    app = create_app(tmp_path, start_scheduler=False)

    @app.post("/api/v1/echo", dependencies=[Depends(check_csrf)])
    def echo() -> dict[str, bool]:
        return {"ok": True}

    with TestClient(app) as test_client:
        token = csrf_from(test_client.get("/login").text)
        assert test_client.post("/api/v1/echo").status_code == 403
        wrong = test_client.post("/api/v1/echo", headers={"X-CSRF-Token": "nope"})
        assert wrong.status_code == 403
        right = test_client.post("/api/v1/echo", headers={"X-CSRF-Token": token})
        assert right.status_code == 200


# --- rate limiting --------------------------------------------------------------


def test_sixth_failed_login_within_the_window_is_429(client: TestClient, admin: str) -> None:
    for _ in range(5):
        assert _post_login(client, "wrong password!!") == 401
    assert _post_login(client, "wrong password!!") == 429
    # Blocked means blocked: even the right password is refused until the window passes.
    assert _post_login(client, ADMIN_PASSWORD) == 429


def test_rate_limit_counts_unknown_usernames_too(client: TestClient, admin: str) -> None:
    for i in range(5):
        assert _post_login(client, "wrong password!!", username=f"user{i}") == 401
    assert _post_login(client, ADMIN_PASSWORD) == 429


def test_rate_limit_lifts_after_the_window(client: TestClient, admin: str) -> None:
    clock = FakeClock()
    app = client.app
    assert isinstance(app, FastAPI)
    app.state.login_limiter = LoginRateLimiter(clock=clock)
    for _ in range(5):
        assert _post_login(client, "wrong password!!") == 401
    assert _post_login(client, ADMIN_PASSWORD) == 429
    clock.now += 301
    assert _post_login(client, ADMIN_PASSWORD) == 303


def test_successful_login_resets_the_counter(client: TestClient, admin: str) -> None:
    for _ in range(4):
        assert _post_login(client, "wrong password!!") == 401
    assert _post_login(client, ADMIN_PASSWORD) == 303
    for _ in range(5):
        assert _post_login(client, "wrong password!!") == 401
    assert _post_login(client, "wrong password!!") == 429


def test_limiter_window_slides() -> None:
    clock = FakeClock()
    limiter = LoginRateLimiter(max_failures=5, window_seconds=300, clock=clock)
    for _ in range(5):
        assert limiter.try_begin("10.0.0.1")
        clock.now += 50
    assert not limiter.try_begin("10.0.0.1")
    assert limiter.try_begin("10.0.0.2")
    clock.now += 51  # the first attempt (t=1000) is now older than 300s
    assert limiter.try_begin("10.0.0.1")


def test_limiter_success_clears_the_ip() -> None:
    limiter = LoginRateLimiter(max_failures=2)
    assert limiter.try_begin("10.0.0.1")
    assert limiter.try_begin("10.0.0.1")
    assert not limiter.try_begin("10.0.0.1")
    limiter.succeeded("10.0.0.1")
    assert limiter.attempts("10.0.0.1") == 0
    assert limiter.try_begin("10.0.0.1")


def test_limiter_admits_at_most_max_attempts_under_concurrency() -> None:
    limiter = LoginRateLimiter(max_failures=5, window_seconds=300)
    barrier = threading.Barrier(32)

    def attempt(_: int) -> bool:
        barrier.wait()
        return limiter.try_begin("10.0.0.1")

    with ThreadPoolExecutor(max_workers=32) as pool:
        admitted = sum(pool.map(attempt, range(32)))
    assert admitted == 5
    assert limiter.attempts("10.0.0.1") == 5


def test_limiter_caps_tracked_ips_evicting_the_oldest() -> None:
    limiter = LoginRateLimiter(max_tracked=3)
    for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"):
        assert limiter.try_begin(ip)
    assert limiter.tracked() == 3
    assert limiter.attempts("10.0.0.1") == 0  # evicted
    assert limiter.attempts("10.0.0.4") == 1


def test_limiter_sweeps_expired_ips_at_most_once_per_interval() -> None:
    clock = FakeClock()  # t=1000
    limiter = LoginRateLimiter(window_seconds=300, sweep_interval=600, clock=clock)
    for i in range(100):
        assert limiter.try_begin(f"10.0.0.{i}")
    clock.now += 301  # all 100 expired, but no sweep is due yet
    assert limiter.try_begin("192.0.2.1")
    assert limiter.tracked() == 101
    clock.now += 300  # 601s since the last sweep: this call sweeps
    assert limiter.try_begin("192.0.2.2")
    assert limiter.tracked() == 1


# --- concurrency through the app ------------------------------------------------


def _parallel(count: int, work: Callable[[int], int]) -> list[int]:
    barrier = threading.Barrier(count)

    def run(i: int) -> int:
        barrier.wait()
        return work(i)

    with ThreadPoolExecutor(max_workers=count) as pool:
        return list(pool.map(run, range(count)))


def test_parallel_wrong_passwords_from_one_ip_get_at_most_five_verifies(
    tmp_path: Path, admin: str
) -> None:
    app = create_app(tmp_path, start_scheduler=False)
    clients = [TestClient(app) for _ in range(20)]
    tokens = [csrf_from(c.get("/login").text) for c in clients]

    def attempt(i: int) -> int:
        response = clients[i].post(
            "/login",
            data={"username": admin, "password": "wrong password!!", "csrf": tokens[i]},
            follow_redirects=False,
        )
        status: int = response.status_code
        return status

    statuses = _parallel(20, attempt)
    assert statuses.count(401) == 5
    assert statuses.count(429) == 15


def test_password_verifications_never_exceed_the_concurrency_bound(
    tmp_path: Path, admin: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock = threading.Lock()
    active = 0
    peak = 0

    def slow_verify(conn: object, username: str, password: str) -> bool:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        time.sleep(0.05)
        with lock:
            active -= 1
        return False

    monkeypatch.setattr(auth, "verify_user", slow_verify)
    app = create_app(tmp_path, start_scheduler=False)
    app.state.login_limiter = LoginRateLimiter(max_failures=1000)
    clients = [TestClient(app) for _ in range(16)]
    tokens = [csrf_from(c.get("/login").text) for c in clients]

    def attempt(i: int) -> int:
        response = clients[i].post(
            "/login",
            data={"username": admin, "password": "wrong password!!", "csrf": tokens[i]},
        )
        status: int = response.status_code
        return status

    statuses = _parallel(16, attempt)
    assert statuses == [401] * 16
    assert 1 <= peak <= auth.MAX_CONCURRENT_VERIFIES


def test_login_is_429_when_no_verification_slot_frees_up(
    client: TestClient, admin: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(auth, "VERIFY_WAIT_SECONDS", 0.01)
    app = client.app
    assert isinstance(app, FastAPI)
    app.state.login_verify_slots = threading.BoundedSemaphore(1)
    app.state.login_verify_slots.acquire()
    token = csrf_from(client.get("/login").text)
    response = client.post(
        "/login", data={"username": admin, "password": ADMIN_PASSWORD, "csrf": token}
    )
    assert response.status_code == 429
    assert "Too many login attempts, try again shortly" in response.text
    assert client.get("/", follow_redirects=False).status_code == 303


# --- sessions die with the user or their password -------------------------------


def test_session_ends_when_the_password_changes(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    assert client.get("/api/v1/me").status_code == 200
    conn = open_db(tmp_path)
    try:
        set_password(conn, ADMIN_USER, "a brand new password")
    finally:
        conn.close()
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert client.get("/api/v1/me").status_code == 401


def test_session_ends_when_the_user_is_deleted(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    conn = open_db(tmp_path)
    try:
        conn.execute("DELETE FROM users WHERE username = ?", (ADMIN_USER,))
    finally:
        conn.close()
    assert client.get("/api/v1/me").status_code == 401
    assert client.get("/", follow_redirects=False).status_code == 303


def test_a_rejected_session_is_cleared(client: TestClient, logged_in: str, tmp_path: Path) -> None:
    conn = open_db(tmp_path)
    try:
        set_password(conn, ADMIN_USER, "a brand new password")
        client.get("/api/v1/me")
        set_password(conn, ADMIN_USER, ADMIN_PASSWORD)  # even the old password back...
    finally:
        conn.close()
    # ...doesn't revive the session: it was cleared when first rejected.
    assert client.get("/api/v1/me").status_code == 401


def test_app_start_up_precomputes_the_dummy_hash(tmp_path: Path) -> None:
    users._dummy_hash.cache_clear()
    create_app(tmp_path, start_scheduler=False)
    assert users._dummy_hash.cache_info().currsize == 1
