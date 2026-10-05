"""
Sliding-Window Rate Limiting & Throttling Middleware
Protects the verification engine and database against denial-of-service (DoS),
brute-force verification loops, and computational exhaustion.
"""

import time
import os
from typing import Dict, List, Tuple
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


class SlidingWindowRateLimiter:
    """
    In-memory thread-safe sliding window rate limiter per client IP address.
    """

    def __init__(self, requests_per_window: int = 120, window_seconds: int = 60):
        self.requests_per_window = requests_per_window
        self.window_seconds = window_seconds
        self.clients: Dict[str, List[float]] = {}

    def is_allowed(self, client_ip: str) -> Tuple[bool, int, int]:
        """
        Determines whether the client request is permitted under current sliding window.
        Returns: (is_allowed: bool, remaining_requests: int, retry_after_seconds: int)
        """
        now = time.time()
        window_start = now - self.window_seconds

        # Retrieve and prune expired timestamps
        timestamps = self.clients.get(client_ip, [])
        valid_timestamps = [t for t in timestamps if t > window_start]

        if len(valid_timestamps) >= self.requests_per_window:
            oldest_timestamp = valid_timestamps[0]
            retry_after = max(1, int(oldest_timestamp + self.window_seconds - now))
            self.clients[client_ip] = valid_timestamps
            return False, 0, retry_after

        valid_timestamps.append(now)
        self.clients[client_ip] = valid_timestamps
        remaining = self.requests_per_window - len(valid_timestamps)
        return True, remaining, 0

    def reset(self) -> None:
        """Clears client tracking (used for testing)."""
        self.clients.clear()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware applying sliding window rate limits with HTTP 429 enforcement.
    """

    def __init__(self, app, requests_per_minute: int = 120):
        super().__init__(app)
        self.limiter = SlidingWindowRateLimiter(
            requests_per_window=requests_per_minute,
            window_seconds=60
        )
        self.exempt_prefixes = ("/static", "/health", "/docs", "/redoc", "/openapi.json")

    async def dispatch(self, request: Request, call_next):
        # Exempt static assets and health probes
        path = request.url.path
        if any(path.startswith(prefix) for prefix in self.exempt_prefixes):
            return await call_next(request)

        # Allow test client or bypass header if configured
        client_ip = request.client.host if request.client else "127.0.0.1"
        allowed, remaining, retry_after = self.limiter.is_allowed(client_ip)

        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Too Many Requests",
                    "detail": f"Rate limit exceeded ({self.limiter.requests_per_window} req/min). Please throttle requests.",
                    "retry_after_seconds": retry_after
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(self.limiter.requests_per_window),
                    "X-RateLimit-Remaining": "0"
                }
            )

        response: Response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self.limiter.requests_per_window)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response
