#!/usr/bin/env python3
"""Compare object access across identities for authorized IDOR testing."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import asdict, dataclass
from string import Template
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


ENV_PATTERN = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}")


def resolve_strings(value: Any) -> Any:
    """Resolve ${ENV_VAR} references without printing their values."""
    if isinstance(value, str):
        return Template(value).safe_substitute(os.environ)
    if isinstance(value, list):
        return [resolve_strings(item) for item in value]
    if isinstance(value, dict):
        return {key: resolve_strings(item) for key, item in value.items()}
    return value


def fingerprint(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()[:16]


@dataclass
class Result:
    request: str
    identity: str
    object_id: str
    owner: str | None
    status: int
    body_length: int
    body_fingerprint: str
    content_type: str
    potential_issue: bool
    error: str | None = None


def perform_request(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None,
    timeout: float,
) -> tuple[int, dict[str, str], bytes]:
    request = Request(url, data=body, headers=headers, method=method.upper())
    try:
        with urlopen(request, timeout=timeout) as response:
            return response.status, dict(response.headers), response.read()
    except HTTPError as error:
        return error.code, dict(error.headers), error.read()


def run(config: dict[str, Any], timeout: float, delay: float) -> list[Result]:
    identities = config["identities"]
    denied_statuses = set(config.get("denied_statuses", [401, 403, 404]))
    results: list[Result] = []

    for request_config in config["requests"]:
        name = request_config["name"]
        method = request_config.get("method", "GET").upper()
        headers = {str(k): str(v) for k, v in request_config.get("headers", {}).items()}
        body_template = request_config.get("body")
        object_ids = [str(item) for item in request_config["object_ids"]]
        owners = {
            str(object_id): owner
            for object_id, owner in request_config.get("object_owners", {}).items()
        }

        for identity, identity_config in identities.items():
            identity_headers = headers | {
                str(k): str(v) for k, v in identity_config.get("headers", {}).items()
            }
            for object_id in object_ids:
                values = {"object_id": object_id}
                url = request_config["url"].format(**values)
                body = None
                if body_template is not None:
                    body = request_config["body"].format(**values).encode()

                try:
                    status, response_headers, response_body = perform_request(
                        method, url, identity_headers, body, timeout
                    )
                    owner = owners.get(object_id)
                    is_owner = owner is None or owner == identity
                    potential_issue = (
                        not is_owner
                        and status not in denied_statuses
                        and status < 400
                    )
                    result = Result(
                        request=name,
                        identity=identity,
                        object_id=object_id,
                        owner=owner,
                        status=status,
                        body_length=len(response_body),
                        body_fingerprint=fingerprint(response_body),
                        content_type=response_headers.get("Content-Type", ""),
                        potential_issue=potential_issue,
                    )
                except (URLError, TimeoutError, ValueError) as error:
                    result = Result(
                        request=name,
                        identity=identity,
                        object_id=object_id,
                        owner=owners.get(object_id),
                        status=0,
                        body_length=0,
                        body_fingerprint="",
                        content_type="",
                        potential_issue=False,
                        error=str(error),
                    )
                results.append(result)
                if delay:
                    time.sleep(delay)
    return results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare object access across explicitly configured identities."
    )
    parser.add_argument("config", help="JSON configuration file")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--output", help="Write JSON results to this file")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        with open(args.config, encoding="utf-8") as config_file:
            config = resolve_strings(json.load(config_file))
        results = run(config, timeout=args.timeout, delay=args.delay)
    except (OSError, KeyError, json.JSONDecodeError) as error:
        print(f"Configuration error: {error}", file=sys.stderr)
        return 2

    payload = [asdict(result) for result in results]
    output = json.dumps(payload, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as output_file:
            output_file.write(output + "\n")

    for result in results:
        marker = "POTENTIAL IDOR" if result.potential_issue else "observed"
        detail = f"error={result.error}" if result.error else (
            f"status={result.status} bytes={result.body_length} "
            f"fingerprint={result.body_fingerprint}"
        )
        print(
            f"[{marker}] {result.request} identity={result.identity} "
            f"object={result.object_id} {detail}"
        )
    return 1 if any(result.potential_issue for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
