"""Fuzzer 引擎 — 多线程并发 FUZZ。"""

import concurrent.futures
import importlib.util
import random
import sys
import time

import requests
from urllib3.exceptions import InsecureRequestWarning

from .detector import block_reason, identify_waf, is_blocked

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Optional: curl_cffi for TLS fingerprint impersonation
_HAS_CURL_CFFI = importlib.util.find_spec("curl_cffi") is not None

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
]


class FuzzResult:
    """单个 FUZZ 测试的结果。"""

    def __init__(self, category, payload, encoding, sent_value, blocked, reason="",
                 status_code=0, response_size=0, elapsed=0.0, exception=None):
        self.category = category
        self.payload = payload
        self.encoding = encoding
        self.sent_value = sent_value
        self.blocked = blocked
        self.reason = reason
        self.status_code = status_code
        self.response_size = response_size
        self.elapsed = elapsed
        self.exception = exception

    def is_bypass(self):
        return not self.blocked

    def to_dict(self):
        return {
            "category": self.category,
            "payload": self.payload,
            "encoding": self.encoding,
            "sent_value": self.sent_value,
            "blocked": self.blocked,
            "reason": self.reason,
            "status_code": self.status_code,
            "response_size": self.response_size,
            "elapsed": round(self.elapsed, 3),
            "exception": str(self.exception) if self.exception else None,
        }


class Fuzzer:
    """FUZZ 引擎。"""

    def __init__(self, target_url, method="GET", param="q", data_param="",
                 custom_headers=None, proxy=None, timeout=10, threads=10,
                 delay=0, user_agent_rotate=False, verify_ssl=False,
                 follow_redirects=False, impersonate=None):
        self.target_url = target_url.rstrip("?")
        self.method = method.upper()
        self.param = param
        self.data_param = data_param or param
        self.custom_headers = custom_headers or {}
        self.proxy = proxy
        self.timeout = timeout
        self.threads = threads
        self.delay = delay
        self.user_agent_rotate = user_agent_rotate
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.impersonate = impersonate  # TLS fingerprint target (e.g. "chrome120")

        self.results = []
        self.bypass_count = 0
        self.blocked_count = 0
        self.total_tests = 0
        self.waf_identified = []
        self.start_time = None
        self._stop = False
        # Shared session for connection pooling + cookie persistence
        self._shared_session = self._create_session()

    def _create_session(self):
        """Create a shared HTTP session with optional TLS impersonation."""
        if self.impersonate and _HAS_CURL_CFFI:
            from curl_cffi.requests import Session
            s = Session(impersonate=self.impersonate, verify=self.verify_ssl)
            if self.proxy:
                s.proxies = {"http": self.proxy, "https": self.proxy}
            return s
        if self.impersonate and not _HAS_CURL_CFFI:
            print("[!] --impersonate requires curl_cffi. Install: pip install curl_cffi")
            print("[!] Falling back to standard requests (no TLS impersonation).")
        s = requests.Session()
        if self.proxy:
            s.proxies = {"http": self.proxy, "https": self.proxy}
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10, pool_maxsize=20, max_retries=0
        )
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        return s

    def _session(self):
        """Return the shared session (connection pooling + cookie jar)."""
        return self._shared_session

    def _headers(self):
        hdrs = dict(self.custom_headers)
        if "User-Agent" not in hdrs:
            if self.user_agent_rotate:
                hdrs["User-Agent"] = random.choice(USER_AGENTS)
            else:
                hdrs["User-Agent"] = USER_AGENTS[0]
        return hdrs

    def _send(self, category, payload, encoding, encoded_value):
        if self._stop:
            return None

        hdrs = self._headers()
        session = self._session()

        try:
            if self.method == "GET":
                params = {self.param: encoded_value}
                resp = session.get(
                    self.target_url, params=params, headers=hdrs,
                    timeout=self.timeout, verify=self.verify_ssl,
                    allow_redirects=self.follow_redirects,
                )
            elif self.method == "POST":
                if self.target_url.endswith("?"):
                    base = self.target_url[:-1]
                else:
                    base = self.target_url
                data = {self.data_param: encoded_value}
                resp = session.post(
                    base, data=data, headers=hdrs,
                    timeout=self.timeout, verify=self.verify_ssl,
                    allow_redirects=self.follow_redirects,
                )
            elif self.method == "PUT":
                resp = session.put(
                    self.target_url, data=encoded_value, headers=hdrs,
                    timeout=self.timeout, verify=self.verify_ssl,
                    allow_redirects=self.follow_redirects,
                )
            elif self.method == "COOKIE":
                hdrs["Cookie"] = f"{self.param}={encoded_value}"
                resp = session.get(
                    self.target_url, headers=hdrs,
                    timeout=self.timeout, verify=self.verify_ssl,
                    allow_redirects=self.follow_redirects,
                )
            elif self.method == "HEADER":
                hdrs[self.param] = encoded_value
                resp = session.get(
                    self.target_url, headers=hdrs,
                    timeout=self.timeout, verify=self.verify_ssl,
                    allow_redirects=self.follow_redirects,
                )
            else:
                raise ValueError(f"Unsupported method: {self.method}")

            blocked = is_blocked(resp)
            reason = block_reason(resp) if blocked else ""
            return FuzzResult(
                category=category, payload=payload, encoding=encoding,
                sent_value=encoded_value, blocked=blocked, reason=reason,
                status_code=resp.status_code, response_size=len(resp.text),
                elapsed=resp.elapsed.total_seconds(),
            )

        except requests.exceptions.Timeout:
            return FuzzResult(
                category=category, payload=payload, encoding=encoding,
                sent_value=encoded_value, blocked=True,
                reason="Timeout", status_code=0,
            )
        except requests.exceptions.ConnectionError:
            return FuzzResult(
                category=category, payload=payload, encoding=encoding,
                sent_value=encoded_value, blocked=True,
                reason="Connection Error", status_code=0,
            )
        except Exception as e:
            return FuzzResult(
                category=category, payload=payload, encoding=encoding,
                sent_value=encoded_value, blocked=True,
                reason=str(e)[:60], status_code=0, exception=e,
            )
        finally:
            session.close()

    def run(self, payloads_and_encodings, progress_cb=None):
        """Run fuzzing against a list of (category, payload, encoding_name, encoded_value)."""
        self.results = []
        self.total_tests = len(payloads_and_encodings)
        self.start_time = time.time()
        self._stop = False

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {}
            for idx, item in enumerate(payloads_and_encodings):
                if self._stop:
                    break
                cat, payload, enc_name, enc_val = item
                f = pool.submit(self._send, cat, payload, enc_name, enc_val)
                futures[f] = idx
                if self.delay > 0:
                    time.sleep(self.delay)

            done = 0
            for future in concurrent.futures.as_completed(futures):
                if self._stop:
                    break
                done += 1
                result = future.result()
                if result is None:
                    continue
                self.results.append(result)

                if result.blocked:
                    self.blocked_count += 1
                else:
                    self.bypass_count += 1

                if progress_cb:
                    if not progress_cb(done, self.total_tests, result):
                        self._stop = True
                        break

        # WAF identification
        if self.results:
            for r in self.results[:min(20, len(self.results))]:
                if r.status_code > 0:
                    fake_resp = type("Resp", (), {"headers": {}, "text": "", "status_code": 0})()
                    # Can't really do WAF ID from FuzzResult, skip here
                    pass

        elapsed = time.time() - self.start_time
        return self.results

    def get_bypass_results(self):
        """Return results that were NOT blocked (potential bypasses)."""
        return [r for r in self.results if r.is_bypass()]

    def get_blocked_results(self):
        return [r for r in self.results if r.blocked]
