"""Minimal VirusTotal v3 client (stdlib only) with caching and rate limiting.

The public API allows 4 requests/minute, so calls are throttled to one every
15 s and every answer is cached on disk for 24 h. URLs are *looked up*, never
detonated by this tool.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, Optional

API = "https://www.virustotal.com/api/v3"
GUI = "https://www.virustotal.com/gui"


def url_id(url: str) -> str:
    """VT identifies a URL by its unpadded urlsafe-base64."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


class VirusTotal:
    def __init__(self, api_key: str, cache_dir: str = ".vt_cache",
                 min_interval: float = 15.0, ttl: int = 86400, timeout: int = 20) -> None:
        self.key = api_key
        self.cache = Path(cache_dir)
        self.cache.mkdir(parents=True, exist_ok=True)
        self.min_interval, self.ttl, self.timeout = min_interval, ttl, timeout
        self._last = 0.0

    # -- plumbing ----------------------------------------------------------
    def _throttle(self) -> None:
        wait = self.min_interval - (time.time() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.time()

    def _request(self, path: str, data: Optional[bytes] = None) -> Optional[dict]:
        self._throttle()
        headers = {"x-apikey": self.key, "accept": "application/json", "user-agent": "phishscope/1.0"}
        if data is not None:
            headers["content-type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(API + path, data=data, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            if exc.code == 429:
                return {"error": "rate_limited"}
            return {"error": f"http_{exc.code}"}
        except (urllib.error.URLError, TimeoutError):
            return {"error": "network"}

    def _cached(self, key: str) -> Optional[dict]:
        f = self.cache / (hashlib.sha1(key.encode()).hexdigest() + ".json")
        if f.exists() and time.time() - f.stat().st_mtime < self.ttl:
            return json.loads(f.read_text())
        return None

    def _store(self, key: str, value: dict) -> None:
        f = self.cache / (hashlib.sha1(key.encode()).hexdigest() + ".json")
        f.write_text(json.dumps(value))

    @staticmethod
    def _summarize(payload: dict, permalink: str) -> Dict[str, object]:
        attrs = payload.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "status": "ok",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "permalink": permalink,
        }

    # -- public API --------------------------------------------------------
    def url(self, target: str) -> Dict[str, object]:
        key = "url:" + target
        if (hit := self._cached(key)) is not None:
            return hit
        uid = url_id(target)
        payload = self._request(f"/urls/{uid}")
        if payload is None:  # never seen before: ask VT to scan it, report later
            self._request("/urls", urllib.parse.urlencode({"url": target}).encode())
            return {"status": "submitted", "permalink": f"{GUI}/url/{uid}"}
        if "error" in payload:
            return {"status": payload["error"]}
        result = self._summarize(payload, f"{GUI}/url/{uid}")
        self._store(key, result)
        return result

    def file(self, sha256: str) -> Dict[str, object]:
        key = "file:" + sha256
        if (hit := self._cached(key)) is not None:
            return hit
        payload = self._request(f"/files/{sha256}")
        if payload is None:
            return {"status": "unknown_to_vt", "permalink": f"{GUI}/file/{sha256}"}
        if "error" in payload:
            return {"status": payload["error"]}
        result = self._summarize(payload, f"{GUI}/file/{sha256}")
        self._store(key, result)
        return result
