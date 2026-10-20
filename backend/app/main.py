import asyncio
import contextlib
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import models  # noqa: F401  (registers tables on Base.metadata)
from .db import Base, engine
from .ingest.watcher import watch_eve_log
from .routes import alerts, assets

logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    watcher = asyncio.create_task(watch_eve_log())
    yield
    watcher.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await watcher


app = FastAPI(title="SentriX", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(alerts.router)
app.include_router(assets.router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
