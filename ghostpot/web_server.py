import os
import re
import mimetypes
from pathlib import Path
from fastapi import FastAPI, Request, Response, HTTPException, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from ghostpot.config import AppConfig
from ghostpot.database import Database

def create_app(config: AppConfig, db: Database) -> FastAPI:
    app = FastAPI(title="Ghostpot Core", docs_url=None, redoc_url=None, openapi_url=None)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["GET"],
        allow_headers=["*"],
    )

    secret_slug = config.web.secret_slug.strip("/")
    prefix = f"/{secret_slug}"
    dist_dir = (Path(__file__).parent.parent / "cowrie_web" / "dist").resolve()
    if not dist_dir.exists():
        dist_dir = Path("cowrie_web/dist").resolve()

    # --- API Routes ---
    @app.get(f"{prefix}/api/stats")
    async def get_stats():
        return await db.get_stats()

    @app.get(f"{prefix}/api/sessions")
    async def get_sessions():
        return await db.get_all_sessions()

    @app.get(f"{prefix}/api/sessions/{{session_id}}")
    async def get_session(session_id: str):
        # Validate session_id format
        if not re.match(r"^[a-zA-Z0-9_-]{4,64}$", session_id):
            raise HTTPException(status_code=400, detail="Invalid session ID format")
        session = await db.get_session_by_id(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        return session

    @app.get(f"{prefix}/api/live")
    async def get_live():
        return await db.get_live_events()

    @app.get(f"{prefix}/api/downloads")
    async def get_downloads():
        return await db.get_all_downloads()

    @app.get(f"{prefix}/api/payloads/{{shasum}}")
    async def download_payload(shasum: str):
        # Strict Path Traversal Prevention
        if not re.match(r"^[a-zA-Z0-9_\-\.]{4,128}$", shasum) or ".." in shasum or "/" in shasum or "\\" in shasum:
            raise HTTPException(status_code=400, detail="Invalid payload hash format")

        downloads_dir = Path(config.storage.downloads_dir).resolve()
        file_path = (downloads_dir / shasum).resolve()

        if not file_path.exists() or not file_path.is_file():
            if downloads_dir.exists():
                for f in os.listdir(downloads_dir):
                    if (f.startswith(shasum) or shasum in f) and not f.startswith("."):
                        candidate = (downloads_dir / f).resolve()
                        if candidate.is_relative_to(downloads_dir) and candidate.is_file():
                            file_path = candidate
                            break

        if not file_path.exists() or not file_path.is_file() or not file_path.is_relative_to(downloads_dir):
            raise HTTPException(status_code=404, detail="Payload binary not found")

        return FileResponse(
            path=file_path,
            filename=file_path.name,
            media_type="application/octet-stream"
        )

    # --- Static Assets & SPA Routing ---
    @app.get(f"{prefix}")
    @app.get(f"{prefix}/")
    async def serve_index():
        index_file = dist_dir / "index.html"
        return FileResponse(index_file, media_type="text/html")

    @app.get(f"{prefix}/assets/{{asset_name:path}}")
    async def serve_assets(asset_name: str):
        asset_path = dist_dir / "assets" / asset_name
        if asset_path.exists() and asset_path.is_file():
            content_type, _ = mimetypes.guess_type(str(asset_path))
            return FileResponse(asset_path, media_type=content_type or "application/octet-stream")
        raise HTTPException(status_code=404, detail="Asset not found")

    @app.get(f"{prefix}/{{file_name}}")
    async def serve_static_file(file_name: str):
        target = dist_dir / file_name
        if target.exists() and target.is_file():
            content_type, _ = mimetypes.guess_type(str(target))
            return FileResponse(target, media_type=content_type or "text/plain")
        # SPA Fallback
        return FileResponse(dist_dir / "index.html", media_type="text/html")

    # --- Middleware for Strict Crawler Defense (Drop anything outside secret prefix) ---
    @app.middleware("http")
    async def crawler_defense_middleware(request: Request, call_next):
        path = request.url.path
        if path == prefix or path.startswith(f"{prefix}/"):
            return await call_next(request)
        # Return pure silent 404 for any port scanners, robots.txt, etc.
        return Response(content="", status_code=status.HTTP_404_NOT_FOUND, media_type="text/plain")

    return app
