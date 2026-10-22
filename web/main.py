"""ngfw-matcher Web UI — FastAPI + HTMX."""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.sessions import SessionMiddleware

from . import config, db
from .deps import base_ctx
from .routers import (auth, compare, devices, find, fullview, hits, match, nat,
                      shadows, snapshot, where_is_use)

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR    = Path(__file__).parent / "static"

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@asynccontextmanager
async def lifespan(app: FastAPI):
    config.warn_if_insecure()
    db.init_db()
    yield


app = FastAPI(title="ngfw-matcher", docs_url=None, redoc_url=None, lifespan=lifespan)
app.add_middleware(
    SessionMiddleware,
    secret_key=config.SECRET_KEY,
    max_age=config.SESSION_MAX_AGE,
    same_site="strict",
    https_only=config.COOKIE_HTTPS_ONLY,
)
app.add_middleware(GZipMiddleware, minimum_size=500)

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Метки SecurityRule created_at / updated_at
from ..core.format import fmt_rule_date, fmt_rule_datetime, rule_days_ago  # noqa: E402
templates.env.filters["rule_date"] = fmt_rule_date
templates.env.filters["rule_datetime"] = fmt_rule_datetime
templates.env.filters["rule_days_ago"] = rule_days_ago
templates.env.globals["rule_recent_days"] = config.RULE_RECENT_DAYS

# Inject templates into routers
for mod in (auth, devices, match, find, shadows, hits, snapshot, fullview, nat, compare, where_is_use):
    mod.templates = templates

app.include_router(auth.router)
app.include_router(devices.router)
app.include_router(compare.router)
app.include_router(match.router)
app.include_router(find.router)
app.include_router(shadows.router)
app.include_router(hits.router)
app.include_router(snapshot.router)
app.include_router(fullview.router)
app.include_router(nat.router)
app.include_router(where_is_use.router)


def _host_of(url: str) -> str:
    try:
        return urlparse(url).netloc
    except ValueError:
        return ""


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """CSRF (Origin/Referer) + baseline security headers.

    The session cookie is SameSite=Strict, so cross-site POSTs already arrive
    without the session; the Origin/Referer check is a second layer.
    """
    if request.method in UNSAFE_METHODS:
        host = request.headers.get("host", "")
        origin = request.headers.get("origin")
        referer = request.headers.get("referer")
        source = origin or referer
        if source and _host_of(source) != host:
            return JSONResponse({"detail": "CSRF check failed"}, status_code=403)

    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; "
        "base-uri 'self'; form-action 'self'",
    )
    return response


if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.middleware("http")
async def static_cache_middleware(request: Request, call_next):
    """Long-lived cache with security headers for static assets."""
    response = await call_next(request)
    if request.url.path.startswith("/static/") and response.status_code == 200:
        response.headers.setdefault("Cache-Control", "public, max-age=31536000, immutable")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    return response


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    if not request.session.get("host") and not request.session.get("offline_snap"):
        return RedirectResponse("/connect")

    ctx = base_ctx(request)
    ctx["host"] = request.session.get("host", "")
    ctx["user"] = request.session.get("user", "")
    return templates.TemplateResponse(request, "index.html", ctx)


def serve():
    import uvicorn
    uvicorn.run("ngfw_matcher.web.main:app", host=config.HOST, port=config.PORT, reload=False)


if __name__ == "__main__":
    serve()
