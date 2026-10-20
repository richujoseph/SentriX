import asyncio
import contextlib
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import models  # noqa: F401  (registers tables on Base.metadata)
from .db import Base, engine
from .correlation.job import run_correlation_loop
from .ingest.watcher import watch_eve_log
from .routes import alerts, assets, incidents

logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    tasks = [
        asyncio.create_task(watch_eve_log()),
        asyncio.create_task(run_correlation_loop()),
    ]
    yield
    for task in tasks:
        task.cancel()
    for task in tasks:
        with contextlib.suppress(asyncio.CancelledError):
            await task


app = FastAPI(title="SentriX", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(alerts.router)
app.include_router(assets.router)
app.include_router(incidents.router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
