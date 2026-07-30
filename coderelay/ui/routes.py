from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from coderelay import __version__
from coderelay.auth import get_container

_UI_DIR = Path(__file__).resolve().parent
TEMPLATES = Jinja2Templates(directory=str(_UI_DIR / "templates"))
router = APIRouter()


def _has_session(request: Request) -> bool:
    container = get_container(request)
    token = request.cookies.get(container.config.security.session_cookie_name, "")
    return container.security.session_signer.verify(token) is not None


@router.get("/", include_in_schema=False)
async def root(request: Request) -> RedirectResponse:
    return RedirectResponse("/app" if _has_session(request) else "/login", status_code=303)


@router.get("/login", response_class=HTMLResponse, include_in_schema=False)
async def login_page(request: Request) -> Response:
    if _has_session(request):
        return RedirectResponse("/app", status_code=303)
    return TEMPLATES.TemplateResponse(request=request, name="login.html", context={"version": __version__})


@router.get("/app", response_class=HTMLResponse, include_in_schema=False)
async def dashboard(request: Request) -> Response:
    if not _has_session(request):
        return RedirectResponse("/login", status_code=303)
    return TEMPLATES.TemplateResponse(request=request, name="dashboard.html", context={"version": __version__})
