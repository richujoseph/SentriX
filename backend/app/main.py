from contextlib import asynccontextmanager

from fastapi import FastAPI

from . import models  # noqa: F401  (registers tables on Base.metadata)
from .db import Base, engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title="SentriX", lifespan=lifespan)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
