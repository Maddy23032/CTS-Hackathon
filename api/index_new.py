# Simplified Vercel handler for FastAPI
import os
import sys
from pathlib import Path

# Try importing FastAPI
try:
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
except ImportError as e:
    # If FastAPI isn't available, create a simple handler
    def simple_handler(environ, start_response):
        status = '200 OK'
        headers = [('Content-Type', 'application/json')]
        start_response(status, headers)
        return [b'{"status": "error", "message": "FastAPI not available"}']
    
    handler = simple_handler
    exit()

# Create a simple FastAPI app that works
app = FastAPI(
    title="VulnScan API",
    description="Vulnerability Scanner API - Serverless Version",
    version="1.0"
)

# Add CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://vulnscan-nine.vercel.app",
        "http://localhost:5173",
        "http://localhost:3000",
        "*"  # Allow all for testing
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Health check endpoints
@app.get("/")
async def root():
    return {
        "message": "VulnScan API v1.0",
        "status": "running",
        "environment": "vercel-serverless"
    }

@app.get("/api/health")
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "message": "Serverless backend is running",
        "platform": "vercel"
    }

@app.get("/api/status")
async def status():
    return {
        "status": "active",
        "version": "1.0",
        "features": ["health-check", "cors-enabled"]
    }

# Basic API endpoints for testing
@app.get("/api/test")
async def test_endpoint():
    return {"test": "success", "message": "API is working"}

# Mock vulnerabilities endpoint for frontend testing
@app.get("/api/vulnerabilities")
async def get_vulnerabilities():
    return {
        "vulnerabilities": [],
        "total": 0,
        "message": "No vulnerabilities found (mock response)"
    }

# Mock scan status endpoint
@app.get("/api/scan/status")
async def get_scan_status():
    return {
        "scanning": False,
        "progress": 0,
        "status": "idle"
    }

# The handler for Vercel
handler = app
