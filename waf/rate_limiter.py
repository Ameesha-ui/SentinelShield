"""
SentinelShield - Behavior Monitoring & Rate Limiter
Tracks request frequencies per IP using a sliding-window algorithm,
identifies flooding/brute-force patterns, and enforces temporary bans.
"""

import time
from typing import Dict, List, Tuple, Optional
from collections import defaultdict
import threading


class RateLimiter:
    def __init__(self, max_requests: int = 15, window_seconds: int = 10, ban_duration_seconds: int = 45):
        """
        :param max_requests: Maximum allowed requests within the time window.
        :param window_seconds: Time window duration in seconds.
        :param ban_duration_seconds: Duration to ban an IP after threshold breach.
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.ban_duration_seconds = ban_duration_seconds

        # Map: IP -> list of timestamps
        self.request_history: Dict[str, List[float]] = defaultdict(list)
        # Map: IP -> ban expiration timestamp
        self.banned_ips: Dict[str, float] = {}
        # Map: IP -> reason for ban
        self.ban_reasons: Dict[str, str] = {}
        # Total counts per IP
        self.total_requests_per_ip: Dict[str, int] = defaultdict(int)
        self.total_blocks_per_ip: Dict[str, int] = defaultdict(int)

        self._lock = threading.Lock()

    def is_ip_banned(self, ip: str) -> Tuple[bool, int, Optional[str]]:
        """
        Checks if an IP is currently banned.
        Returns (is_banned, seconds_remaining, reason).
        """
        with self._lock:
            now = time.time()
            if ip in self.banned_ips:
                expiry = self.banned_ips[ip]
                if now < expiry:
                    return True, int(expiry - now), self.ban_reasons.get(ip, "Excessive rate limit breaches")
                else:
                    # Ban expired
                    del self.banned_ips[ip]
                    if ip in self.ban_reasons:
                        del self.ban_reasons[ip]
            return False, 0, None

    def record_and_evaluate(self, ip: str) -> Tuple[bool, str, int]:
        """
        Records an incoming request from an IP and checks sliding window limits.
        Returns:
            allowed (bool): True if allowed, False if rate limited.
            message (str): Diagnostic details.
            requests_in_window (int): Count of requests in active window.
        """
        with self._lock:
            now = time.time()
            self.total_requests_per_ip[ip] += 1

            # Check if already banned
            if ip in self.banned_ips:
                expiry = self.banned_ips[ip]
                if now < expiry:
                    self.total_blocks_per_ip[ip] += 1
                    rem = int(expiry - now)
                    return False, f"IP {ip} is temporarily banned. Ban expires in {rem}s.", len(self.request_history[ip])
                else:
                    del self.banned_ips[ip]
                    if ip in self.ban_reasons:
                        del self.ban_reasons[ip]

            # Prune timestamps older than window
            cutoff = now - self.window_seconds
            self.request_history[ip] = [ts for ts in self.request_history[ip] if ts > cutoff]

            # Add current request
            self.request_history[ip].append(now)
            count = len(self.request_history[ip])

            # Check threshold
            if count > self.max_requests:
                # Ban IP
                self.banned_ips[ip] = now + self.ban_duration_seconds
                self.ban_reasons[ip] = f"Exceeded rate limit: {count} requests within {self.window_seconds}s (limit: {self.max_requests})"
                self.total_blocks_per_ip[ip] += 1
                return False, f"Rate limit exceeded: {count}/{self.max_requests} reqs in {self.window_seconds}s. Banned for {self.ban_duration_seconds}s.", count

            return True, f"Request within limits ({count}/{self.max_requests}).", count

    def ban_ip(self, ip: str, duration_seconds: Optional[int] = None, reason: str = "Manual security ban"):
        with self._lock:
            dur = duration_seconds or self.ban_duration_seconds
            self.banned_ips[ip] = time.time() + dur
            self.ban_reasons[ip] = reason
            self.total_blocks_per_ip[ip] += 1

    def unban_ip(self, ip: str) -> bool:
        with self._lock:
            existed = ip in self.banned_ips
            if existed:
                del self.banned_ips[ip]
            if ip in self.ban_reasons:
                del self.ban_reasons[ip]
            self.request_history[ip] = []
            return existed

    def get_tracked_ips(self) -> List[Dict]:
        with self._lock:
            now = time.time()
            cutoff = now - self.window_seconds
            results = []
            all_ips = set(self.request_history.keys()).union(set(self.banned_ips.keys()))

            for ip in all_ips:
                recent_reqs = len([t for t in self.request_history.get(ip, []) if t > cutoff])
                is_banned = ip in self.banned_ips and now < self.banned_ips[ip]
                expiry_seconds = int(self.banned_ips[ip] - now) if is_banned else 0

                results.append({
                    "ip": ip,
                    "active_requests_in_window": recent_reqs,
                    "total_requests": self.total_requests_per_ip.get(ip, 0),
                    "total_blocks": self.total_blocks_per_ip.get(ip, 0),
                    "is_banned": is_banned,
                    "ban_expires_in": expiry_seconds,
                    "ban_reason": self.ban_reasons.get(ip, "N/A") if is_banned else None
                })
            return results

    def reset(self):
        with self._lock:
            self.request_history.clear()
            self.banned_ips.clear()
            self.ban_reasons.clear()
            self.total_requests_per_ip.clear()
            self.total_blocks_per_ip.clear()

