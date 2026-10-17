# Pin excerpt of py/pfapi/api/services/get_acb.py
# github.com/Netgate/pfsense-api b4acd7ca21dbca739a530403a1f62a7440f7726f
# Apache-2.0 generated client. Host-side prove() greps this text. Not imported.

from typing import Any


def _get_kwargs(
    *,
    userkey: str,
    revision: str,
) -> dict[str, Any]:
    params: dict[str, Any] = {}

    params["userkey"] = userkey

    params["revision"] = revision

    params = {k: v for k, v in params.items() if v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/services/acb/bkp",
        "params": params,
    }

    return _kwargs
