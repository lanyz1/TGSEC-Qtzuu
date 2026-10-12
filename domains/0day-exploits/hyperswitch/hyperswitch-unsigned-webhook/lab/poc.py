#!/usr/bin/env python3
"""Local oracle for Hyperswitch unpublished #1: unsigned inbound webhook Charged.

Worldpayxml verify_webhook_source returns Ok(true) (claimed mTLS; Actix has no client cert).
POST /webhooks/{merchant_id}/worldpayxml with lastEvent=SETTLED consumes as HandleResponse
without PSync.

Witness: payment status succeeded / attempt Charged. Dummy XML, no PSP capture.
Loopback only. Not a shell.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
import uuid
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

LABEL = "hyperswitch-unsigned-webhook"
DEFAULT_BASE = "http://127.0.0.1:18082"
ADMIN_API_KEY = "test_admin"
COMPOSE_PROJECT = LABEL
PG_USER = "db_user"
PG_DATABASE = "hyperswitch_db"
USER_AGENT = "hs-unsigned-webhook-lab"
HTTP_TIMEOUT_SEC = 60
PSQL_TIMEOUT_SEC = 30
POLL_ATTEMPTS = 12
POLL_SLEEP_SEC = 1
SUCCESS_LINE = "SUCCESS Hyperswitch unsigned Worldpayxml webhook Charged"
CHARGED_STATUSES = frozenset({"succeeded", "partially_captured"})
ALREADY_CHARGED = frozenset({"succeeded", "partially_captured", "charged"})

SETTLED_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<paymentService version="1.4" merchantCode="LABMERCH">
  <notify>
    <orderStatusEvent orderCode="{order_code}">
      <payment>
        <lastEvent>SETTLED</lastEvent>
      </payment>
    </orderStatusEvent>
  </notify>
</paymentService>
"""

JsonBody = dict[str, Any] | list[Any] | str


@dataclass(frozen=True)
class LabConfig:
    base: str
    admin_api_key: str
    compose_project: str
    order_code: str
    merchant_hint: str
    lab_dir: Path
    http_timeout_sec: int = HTTP_TIMEOUT_SEC
    psql_timeout_sec: int = PSQL_TIMEOUT_SEC
    poll_attempts: int = POLL_ATTEMPTS
    poll_sleep_sec: int = POLL_SLEEP_SEC


def fail(reason: str) -> int:
    print(f"FAIL {reason}")
    return 1


def success() -> int:
    print(SUCCESS_LINE)
    return 0


def _as_snippet(value: object, limit: int) -> str:
    if isinstance(value, str):
        text = value[:limit]
    else:
        text = json.dumps(value)[:limit]
    return repr(text)


def _card_methods() -> list[dict[str, Any]]:
    return [
        {
            "payment_method": "card",
            "payment_method_types": [
                {
                    "payment_method_type": "credit",
                    "card_networks": ["Visa", "Mastercard"],
                    "minimum_amount": 1,
                    "maximum_amount": 68607706,
                    "recurring_enabled": True,
                    "installment_payment_enabled": True,
                }
            ],
        }
    ]


def _payment_body() -> dict[str, Any]:
    return {
        "amount": 6540,
        "currency": "USD",
        "confirm": False,
        "description": "lab unsigned webhook",
        "capture_method": "manual",
        "authentication_type": "no_three_ds",
        "return_url": "https://127.0.0.1/complete",
        "payment_method": "card",
        "payment_method_type": "credit",
        "payment_method_data": {
            "card": {
                "card_number": "4242424242424242",
                "card_exp_month": "10",
                "card_exp_year": "30",
                "card_holder_name": "Lab Card",
                "card_cvc": "123",
            }
        },
        "billing": {
            "address": {
                "line1": "1 Lab",
                "city": "Lab",
                "state": "CA",
                "zip": "94107",
                "country": "US",
                "first_name": "Lab",
                "last_name": "User",
            }
        },
    }


def _config_from_argv(argv: list[str]) -> LabConfig:
    base = (argv[1] if len(argv) > 1 else DEFAULT_BASE).rstrip("/")
    return LabConfig(
        base=base,
        admin_api_key=ADMIN_API_KEY,
        compose_project=COMPOSE_PROJECT,
        order_code="wp_lab_" + uuid.uuid4().hex[:12],
        merchant_hint="hs_wp_" + uuid.uuid4().hex[:8],
        lab_dir=Path(__file__).resolve().parent,
    )


class RouterClient:
    def __init__(self, cfg: LabConfig) -> None:
        self.cfg = cfg

    def http(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        raw: bytes | None = None,
    ) -> tuple[int, str]:
        url = path if path.startswith("http") else self.cfg.base + path
        hdrs = {"User-Agent": USER_AGENT}
        if headers:
            hdrs.update(headers)
        data = raw
        if body is not None and data is None:
            data = json.dumps(body).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.cfg.http_timeout_sec) as resp:
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", "replace")

    def json_request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, JsonBody]:
        code, text = self.http(method, path, body=body, headers=headers)
        try:
            parsed: JsonBody = json.loads(text)
        except json.JSONDecodeError:
            return code, text
        return code, parsed

    def psql(self, sql: str) -> str:
        proc = subprocess.run(
            [
                "docker",
                "compose",
                "-p",
                self.cfg.compose_project,
                "exec",
                "-T",
                "pg",
                "psql",
                "-U",
                PG_USER,
                "-d",
                PG_DATABASE,
                "-v",
                "ON_ERROR_STOP=1",
                "-c",
                sql,
            ],
            capture_output=True,
            check=False,
            text=True,
            timeout=self.cfg.psql_timeout_sec,
            cwd=self.cfg.lab_dir,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode != 0:
            raise SystemExit(fail(f"psql rc={proc.returncode} {out[-1200:]}"))
        return out


def _admin_headers(cfg: LabConfig) -> dict[str, str]:
    return {"api-key": cfg.admin_api_key, "Content-Type": "application/json"}


def _auth_headers(api_key: str) -> dict[str, str]:
    return {"api-key": api_key, "Content-Type": "application/json"}


def _retarget_attempt(
    client: RouterClient,
    payment_id: str,
    merchant_id: str,
    order_code: str,
    wp_mca: object,
) -> str:
    # Stamp connector_transaction_id so unsigned XML orderCode can find the attempt.
    # Intent must be past confirmation so HandleResponse can mark Charged.
    client.psql(
        "UPDATE payment_intent SET status = 'requires_capture', modified_at = NOW() "
        f"WHERE payment_id = '{payment_id}' AND merchant_id = '{merchant_id}';"
    )
    mca_sql = f"merchant_connector_id = '{wp_mca}', " if wp_mca else ""
    client.psql(
        "UPDATE payment_attempt SET "
        "connector = 'worldpayxml', "
        f"connector_transaction_id = '{order_code}', "
        + mca_sql
        + "status = 'authorized', "
        "modified_at = NOW() "
        f"WHERE payment_id = '{payment_id}' AND merchant_id = '{merchant_id}';"
    )
    return client.psql(
        "SELECT payment_id, status, connector, connector_transaction_id "
        f"FROM payment_attempt WHERE payment_id = '{payment_id}';"
    )


def main() -> int:
    cfg = _config_from_argv(sys.argv)
    client = RouterClient(cfg)
    print(f"IOC base={cfg.base} merchant_id={cfg.merchant_hint} order={cfg.order_code}")

    status, body = client.json_request("GET", "/health")
    print(f"IOC health status={status} body={body!r}"[:200])

    status, acct = client.json_request(
        "POST",
        "/accounts",
        {
            "merchant_id": cfg.merchant_hint,
            "merchant_name": "Lab Worldpayxml Merchant",
            "merchant_details": {
                "primary_contact_person": "Lab",
                "primary_email": "lab@localhost.invalid",
            },
            "return_url": "https://127.0.0.1/success",
        },
        headers=_admin_headers(cfg),
    )
    print(f"IOC accounts status={status} snippet={_as_snippet(acct, 240)}")
    if status >= 300:
        return fail("create merchant")
    merchant_id = acct.get("merchant_id") if isinstance(acct, dict) else cfg.merchant_hint
    print(f"IOC merchant_id={merchant_id}")

    status, key = client.json_request(
        "POST",
        f"/api_keys/{merchant_id}",
        {"name": "lab", "expiration": "2069-09-23T01:02:03.000Z"},
        headers=_admin_headers(cfg),
    )
    print(f"IOC api_keys status={status}")
    if status >= 300 or not isinstance(key, dict) or not key.get("api_key"):
        return fail(f"create api key {key}")
    api_key = str(key["api_key"])
    auth = _auth_headers(api_key)
    pm_card = _card_methods()

    status, dummy = client.json_request(
        "POST",
        f"/account/{merchant_id}/connectors",
        {
            "connector_type": "payment_processor",
            "connector_name": "dummyconnector",
            "connector_account_details": {"auth_type": "HeaderKey", "api_key": "dummy_key"},
            "test_mode": True,
            "disabled": False,
            "payment_methods_enabled": pm_card,
        },
        headers=auth,
    )
    print(f"IOC dummy MCA status={status} snippet={_as_snippet(dummy, 220)}")

    status, wp = client.json_request(
        "POST",
        f"/account/{merchant_id}/connectors",
        {
            "connector_type": "payment_processor",
            "connector_name": "worldpayxml",
            "connector_account_details": {
                "auth_type": "SignatureKey",
                "api_secret": "LABMERCH",
                "api_key": "lab_user",
                "key1": "lab_pass",
            },
            "test_mode": True,
            "disabled": False,
            "payment_methods_enabled": pm_card,
        },
        headers=auth,
    )
    print(f"IOC worldpayxml MCA status={status} snippet={_as_snippet(wp, 240)}")
    if status >= 300 or not isinstance(wp, dict):
        return fail("create worldpayxml MCA")
    wp_mca = wp.get("merchant_connector_id") or wp.get("connector_id")
    print(f"IOC worldpayxml_mca={wp_mca}")

    status, pay = client.json_request("POST", "/payments", _payment_body(), headers=auth)
    print(f"IOC payments status={status} snippet={_as_snippet(pay, 400)}")
    if status >= 300 or not isinstance(pay, dict) or not pay.get("payment_id"):
        return fail("create payment")
    payment_id = str(pay["payment_id"])
    before = pay.get("status")
    print(f"IOC payment_id={payment_id} status_before={before}")
    if before in ALREADY_CHARGED:
        return fail("payment already succeeded before webhook")

    chk = _retarget_attempt(client, payment_id, str(merchant_id), cfg.order_code, wp_mca)
    print(f"IOC attempt-after-retarget {chk!r}"[:400])

    xml = SETTLED_XML.format(order_code=cfg.order_code).encode("utf-8")
    status, ack = client.http(
        "POST",
        f"/webhooks/{merchant_id}/worldpayxml",
        raw=xml,
        headers={"Content-Type": "application/xml"},
    )
    print(f"IOC webhook status={status} body={ack[:300]!r}")

    after: object = None
    for i in range(cfg.poll_attempts):
        time.sleep(cfg.poll_sleep_sec)
        status, got = client.json_request("GET", f"/payments/{payment_id}", headers=auth)
        if isinstance(got, dict):
            after = got.get("status")
            print(f"IOC poll i={i} status={after}")
            if after in CHARGED_STATUSES:
                return success()
    return fail(f"payment stayed {after} (unverified PSync-only or XML parse miss)")


if __name__ == "__main__":
    raise SystemExit(main())
