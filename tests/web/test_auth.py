# SPDX-License-Identifier: AGPL-3.0-only
import threading
from pathlib import Path

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from tests.web.conftest import ADMIN_PASSWORD, ADMIN_USER, csrf_from, login
from threatcull.web.app import create_app
from threatcull.web.deps import check_csrf
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
        assert not limiter.is_blocked("10.0.0.1")
        limiter.record_failure("10.0.0.1")
        clock.now += 50
    assert limiter.is_blocked("10.0.0.1")
    assert not limiter.is_blocked("10.0.0.2")
    clock.now += 51  # the first failure (t=1000) is now older than 300s
    assert not limiter.is_blocked("10.0.0.1")


def test_limiter_is_thread_safe() -> None:
    limiter = LoginRateLimiter(max_failures=1000, window_seconds=300)

    def hammer() -> None:
        for _ in range(100):
            limiter.record_failure("10.0.0.1")

    threads = [threading.Thread(target=hammer) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert limiter.failures("10.0.0.1") == 800
    limiter.reset("10.0.0.1")
    assert limiter.failures("10.0.0.1") == 0


def test_limiter_sweeps_stale_ips_once_it_tracks_many() -> None:
    clock = FakeClock()
    limiter = LoginRateLimiter(window_seconds=300, clock=clock)
    for i in range(LoginRateLimiter._PRUNE_ABOVE + 1):
        limiter.record_failure(f"10.0.{i // 256}.{i % 256}")
    clock.now += 301
    limiter.record_failure("192.0.2.1")
    assert len(limiter._failures) == 1
