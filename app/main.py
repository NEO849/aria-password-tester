"""FastAPI-App: statische Auslieferung + /api/analyze Endpunkt.

Methoden-Übersicht:
  analyze(req)          -> POST /api/analyze: führt Analyse + HIBP aus
  health()              -> GET /api/health
  root()                -> liefert die index.html
"""
import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.breach import check_breach
from app.config import settings
from app.models import AnalyzeRequest, AnalyzeResponse
from app.strength import analyze

logging.basicConfig(
    level=settings.log_level,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
)
log = logging.getLogger("aria")

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="ARIA Password Tester", version="1.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_list(),
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/api/health")
async def health() -> dict:
    """Healthcheck."""
    return {"status": "ok"}


@app.post("/api/analyze", response_model=AnalyzeResponse)
@limiter.limit(settings.rate_limit)
async def analyze_endpoint(request: Request, req: AnalyzeRequest) -> AnalyzeResponse:
    """Führt Passwortanalyse aus. Passwort wird NICHT geloggt oder gespeichert."""
    result = analyze(req.password)

    breached, count = (None, None)
    if settings.enable_hibp:
        breached, count = check_breach(req.password)

    return AnalyzeResponse(
        length=result["length"],
        entropy_bits=result["entropy_bits"],
        zxcvbn_score=result["zxcvbn_score"],
        patterns=result["patterns"],
        feedback=result["feedback"],
        crack_times=result["crack_times"],
        breached=breached,
        breach_count=count,
        verdict=result["verdict"],
        verdict_level=result["verdict_level"],
    )


@app.get("/")
async def root() -> FileResponse:
    """Liefert die Startseite."""
    return FileResponse(STATIC_DIR / "index.html")


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception) -> JSONResponse:
    """Fängt unerwartete Fehler ab, ohne Details zu leaken."""
    log.exception("Unhandled error")
    return JSONResponse(status_code=500, content={"detail": "Interner Fehler"})
