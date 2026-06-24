# Developed by Ilya Semennikov
from __future__ import annotations

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .. import db
from ..deps import session
from ..._version import __version__

router = APIRouter()
templates: Jinja2Templates = None  # injected from main


@router.get("/connect", response_class=HTMLResponse)
async def connect_page(request: Request):
    return templates.TemplateResponse(request, "connect.html", {"app_version": __version__})


@router.post("/connect")
async def do_connect(
    request: Request,
    host: str = Form(...),
    user: str = Form(...),
    password: str = Form(...),
):
    if not user.strip().lower().endswith("ro"):
        return templates.TemplateResponse(request, "connect.html", {
            "error": "Используйте RO учётную запись",
            "host": host,
            "user": user,
            "app_version": __version__,
        })

    from ...sources.ngfw_api import NGFWDirectSource
    src = NGFWDirectSource(host=host, username=user, password=password,
                           verify_ssl=False)
    try:
        tok = src.login()
    except Exception as e:
        return templates.TemplateResponse(request, "connect.html", {
            "error": str(e),
            "host": host,
            "user": user,
            "app_version": __version__,
        })

    # Сбрасываем данные только для этой СУ (другие СУ не трогаем)
    db.clear_devices_for_host(src.base_url)

    try:
        groups = src.get_device_groups()
        for g in groups:
            db.upsert_device(g["id"], g.get("name", g["id"]),
                             g.get("_path", ""), host=src.base_url)
    except Exception:
        groups = []

    request.session["host"]  = src.base_url
    request.session["token"] = tok
    request.session["user"]  = user
    return RedirectResponse("/", status_code=303)


@router.post("/disconnect")
async def disconnect(request: Request):
    db.clear_all_devices()
    request.session.clear()
    return RedirectResponse("/connect", status_code=303)
