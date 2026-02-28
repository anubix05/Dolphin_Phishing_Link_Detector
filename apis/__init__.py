"""
apis/__init__.py

Exposes the check() function from every API module so callers can do:

    from apis import virustotal, urlscan, google_safe_browsing

Each module must implement:

    def check(url: str) -> dict:
        ...
        return {"score": <0-100>, "source": "<api_name>"}
"""
