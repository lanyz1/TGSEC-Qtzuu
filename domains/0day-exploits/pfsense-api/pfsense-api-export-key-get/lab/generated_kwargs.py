"""Vendored generated _get_kwargs from Netgate/pfsense-api pin b4acd7c.

Source modules (py/pfapi/api/system/):
  download_ca_key.py  GET /system/certauth/{refid}/export-key
  get_cert_key.py     GET /system/certificates/{refid}/export-key
  get_cert_p12.py     GET /system/certificates/{refid}/export-p12

Bodies are identical to the generated functions: method + quoted URL, no headers.
"""

from typing import Any
from urllib.parse import quote


def download_ca_key_get_kwargs(refid: str) -> dict[str, Any]:
    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/system/certauth/{refid}/export-key".format(
            refid=quote(str(refid), safe=""),
        ),
    }
    return _kwargs


def get_cert_key_get_kwargs(refid: str) -> dict[str, Any]:
    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/system/certificates/{refid}/export-key".format(
            refid=quote(str(refid), safe=""),
        ),
    }
    return _kwargs


def get_cert_p12_get_kwargs(refid: str) -> dict[str, Any]:
    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/system/certificates/{refid}/export-p12".format(
            refid=quote(str(refid), safe=""),
        ),
    }
    return _kwargs
