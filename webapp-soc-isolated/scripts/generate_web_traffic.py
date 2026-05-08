"""Generate normal and suspicious traffic for the web SOC demo app."""

from __future__ import annotations

import argparse
import random
import time

import requests


NORMAL_PATHS = ["/", "/health", "/products?limit=5", "/products?limit=10"]
SCAN_PATHS = ["/.git/config", "/wp-admin", "/phpmyadmin", "/etc/passwd"]


def safe_get(session: requests.Session, base_url: str, path: str, headers: dict | None = None) -> None:
    try:
        session.get(base_url + path, timeout=4, headers=headers or {})
    except requests.RequestException as exc:
        print(f"[WARN] GET failed for {path}: {exc}")


def safe_post(session: requests.Session, base_url: str, path: str, payload: dict, headers: dict | None = None) -> None:
    try:
        session.post(base_url + path, json=payload, timeout=4, headers=headers or {})
    except requests.RequestException as exc:
        print(f"[WARN] POST failed for {path}: {exc}")


def normal_traffic(session: requests.Session, base_url: str, count: int) -> None:
    print(f"[INFO] Sending normal traffic ({count} requests)")
    for _ in range(count):
        path = random.choice(NORMAL_PATHS)
        safe_get(session, base_url, path, headers={"x-user": "normal-user", "x-role": "user"})
        time.sleep(random.uniform(0.02, 0.15))


def suspicious_traffic(session: requests.Session, base_url: str, login_attempts: int, scan_attempts: int, admin_attempts: int) -> None:
    print(f"[INFO] Sending suspicious login burst ({login_attempts} attempts)")
    for i in range(login_attempts):
        payload = {"username": f"admin{i % 3}", "password": "wrong_password"}
        safe_post(session, base_url, "/login", payload, headers={"x-user": "attacker", "x-role": "guest"})

    print(f"[INFO] Sending endpoint scan requests ({scan_attempts} attempts)")
    for _ in range(scan_attempts):
        safe_get(session, base_url, random.choice(SCAN_PATHS), headers={"x-user": "attacker", "x-role": "guest"})

    print(f"[INFO] Sending unauthorized admin attempts ({admin_attempts} attempts)")
    for _ in range(admin_attempts):
        safe_get(session, base_url, "/admin", headers={"x-user": "attacker", "x-role": "guest"})


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate synthetic web traffic for SOC testing")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--normal-count", type=int, default=80)
    parser.add_argument("--login-attempts", type=int, default=50)
    parser.add_argument("--scan-attempts", type=int, default=30)
    parser.add_argument("--admin-attempts", type=int, default=25)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    session = requests.Session()

    normal_traffic(session, args.base_url, args.normal_count)
    suspicious_traffic(session, args.base_url, args.login_attempts, args.scan_attempts, args.admin_attempts)

    print("[INFO] Traffic generation complete. Continue with feature engineering.")


if __name__ == "__main__":
    main()
