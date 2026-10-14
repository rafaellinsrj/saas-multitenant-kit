from fastapi import FastAPI

from app.api.routes import router


def create_app() -> FastAPI:
    app = FastAPI(title="saas-multitenant-kit", version="0.1.0")
    app.include_router(router)

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"ok": True}

    return app


app = create_app()
