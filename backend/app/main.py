from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import os

from app.api.v1.auth_routes import router as auth_router
from app.api.v1.mfa_face_routes import router as mfa_face_router
from app.api.v1.vault_routes import router as vault_router  # ✅
from app.api.v1 import admin_routes
from app.api.v1.vault_routes import router as vault_router

app = FastAPI(
    title="Password Manager MFA Backend",
    description="Secure system using SRP + Face MFA + Encrypted Vault",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1",
        "http://localhost",
        "http://127.0.0.1:8000",
        "http://localhost:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../frontend"))
app.mount("/frontend", StaticFiles(directory=FRONTEND_DIR), name="frontend")

app.include_router(auth_router, prefix="/auth", tags=["Auth"])
app.include_router(mfa_face_router)      # /mfa/face/...
app.include_router(vault_router)         # /vault/...
app.include_router(admin_routes.router)
app.include_router(vault_router)


@app.get("/")
def root():
    return {"status": "Backend running"}
