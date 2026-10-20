from fastapi import FastAPI

app = FastAPI(title="SentriX")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
