"""
Zero Trust Policy Verification Engine (ZTPVE)
FastAPI Main Application Entrypoint
"""

import os
import logging
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
import time

from backend.api import policy_router, experiments_router

# Configure clean logging format
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [ZTPVE] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("ztpve.server")

app = FastAPI(
    title="Zero Trust Policy Verification Engine (ZTPVE)",
    description=(
        "Formal verification system for Zero Trust access control workflows using "
        "Finite State Machines (FSMs) and Theory of Computation invariants."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Middleware configuration
allowed_origins = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:3000",
    "*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def audit_and_timing_middleware(request: Request, call_next):
    start_time = time.perf_counter()
    response = await call_next(request)
    process_time = (time.perf_counter() - start_time) * 1000.0
    response.headers["X-Process-Time-Ms"] = f"{process_time:.2f}"
    
    # Exclude static assets from noisy logs
    if not request.url.path.startswith("/static"):
        logger.info(f"{request.method} {request.url.path} -> Status {response.status_code} ({process_time:.2f}ms)")
    return response


# Include API Routers
app.include_router(policy_router, prefix="/api")
app.include_router(experiments_router, prefix="/api")


@app.get("/health", tags=["System"])
def health_check():
    """Health check endpoint for AWS Load Balancers & container orchestration."""
    storage_type = os.getenv("STORAGE_BACKEND", "sqlite")
    return {
        "status": "healthy",
        "service": "zero-trust-policy-verification-engine",
        "version": "1.0.0",
        "storage_backend": storage_type,
        "theory_of_computation_core": "operational"
    }


# Static frontend files
frontend_dir = Path(__file__).resolve().parent.parent / "frontend"
if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

    @app.get("/", include_in_schema=False)
    def serve_frontend_root():
        index_file = frontend_dir / "index.html"
        if index_file.exists():
            return FileResponse(index_file)
        return JSONResponse({"message": "ZTPVE API Running. Frontend index.html not found."})
