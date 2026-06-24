"""ngfw-matcherer Web UI — FastAPI + HTMX."""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from . import db
from .deps import base_ctx
from .routers import auth, devices, find, hits, match, shadows, snapshot

SECRET_KEY = "ngfw-matcher-secret-change-in-prod"

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR    = Path(__file__).parent / "static"

app = FastAPI(title="ngfw-matcher", docs_url=None, redoc_url=None)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, max_age=86400)

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Inject templates into routers
for mod in (auth, devices, match, find, shadows, hits, snapshot):
    mod.templates = templates

app.include_router(auth.router)
app.include_router(devices.router)
app.include_router(match.router)
app.include_router(find.router)
app.include_router(shadows.router)
app.include_router(hits.router)
app.include_router(snapshot.router)

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.on_event("startup")
async def startup():
    db.init_db()


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
    uvicorn.run("ngfw_matcher.web.main:app", host="0.0.0.0", port=8080, reload=False)


if __name__ == "__main__":
    serve()
