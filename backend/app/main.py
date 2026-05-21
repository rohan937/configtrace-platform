from fastapi import FastAPI

app = FastAPI(title="ConfigTrace API", version="0.1.0")


@app.get("/")
def root():
    return {"service": "ConfigTrace API", "status": "ok"}
