# Vercel handler wrapper for FastAPI
import os
import sys
from pathlib import Path

# Add current directory to path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))
sys.path.insert(0, str(current_dir.parent / "backend"))

try:
    from api_server import app
    
    # Ensure proper initialization for Vercel
    if not hasattr(app, '_vercel_initialized'):
        app._vercel_initialized = True
        
        # Add health check endpoint
        @app.get("/api/health")
        async def health_check():
            return {"status": "healthy", "message": "Backend is running on Vercel"}
    
    handler = app
    
except Exception as e:
    # Fallback handler
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    
    fallback_app = FastAPI()
    
    # Add CORS
    fallback_app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    @fallback_app.get("/api/health")
    async def health():
        return {"status": "error", "message": f"Failed to load main app: {str(e)}"}
    
    @fallback_app.get("/")
    async def root():
        return {"message": "VulnScan API Fallback", "error": str(e)}
    
    handler = fallback_app
