#!/usr/bin/env python3
"""
Startgate File Retrieval Service
Retrieves files from app filestore based on database and file hash.
Startgate - Your gateway to efficient file access.
"""

import os
import logging
import zipfile
from pathlib import Path
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Depends, Security, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel, field_validator
import uvicorn
import io

# Configuration from environment variables
SYSTEM_FILESTORE_PATH = os.getenv("SYSTEM_FILESTORE_PATH")
APP_FILESTORE_PATH = os.getenv("APP_FILESTORE_PATH") 
BTBLK_FILESTORE_PATH = os.getenv("BTBLK_FILESTORE_PATH")
DECIMAL_FILESTORE_PATH = os.getenv("DECIMAL_FILESTORE_PATH")
SRM_FILESTORE_PATH = os.getenv("SRM_FILESTORE_PATH")
PORTAL_FILESTORE_PATH = os.getenv("PORTAL_FILESTORE_PATH")

API_TOKEN = os.getenv("API_TOKEN")
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
MAX_FILES_PER_REQUEST = int(os.getenv("MAX_FILES_PER_REQUEST", "100"))
EXPECTED_HASH_LENGTH = 40  # SHA-1 hash length

# Service mapping
SERVICES = {
    "system": SYSTEM_FILESTORE_PATH,
    "app": APP_FILESTORE_PATH,
    "btblk": BTBLK_FILESTORE_PATH,
    "decimal": DECIMAL_FILESTORE_PATH,
    "srm": SRM_FILESTORE_PATH,
    "portal": PORTAL_FILESTORE_PATH
}

# Validate required configuration
if not API_TOKEN:
    raise ValueError("API_TOKEN environment variable is required")

# Validate at least one service is configured
configured_services = {name: path for name, path in SERVICES.items() if path}
if not configured_services:
    raise ValueError("At least one *_FILESTORE_PATH environment variable must be configured")

# Update services to only include configured ones
SERVICES = configured_services

# Configure logging
logging.basicConfig(level=getattr(logging, LOG_LEVEL))
logger = logging.getLogger(__name__)

# Security
security = HTTPBearer()
VALID_TOKENS = {API_TOKEN}

app = FastAPI(
    title="Startgate File Retrieval Service",
    description="High-performance file retrieval service with direct binary streaming",
    version="1.0.0",
    docs_url=None,  # Disable automatic API docs for security
    redoc_url=None  # Disable automatic ReDoc for security
)

# Add security headers middleware
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# Global exception handler to prevent path disclosure
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # Log the actual error internally (you can configure proper logging)
    print(f"Error: {exc}")
    
    # Return generic error message without exposing internals
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error"}
    )

class FileRequest(BaseModel):
    """Request model for file retrieval."""
    files: List[str]
    always_zip: bool = True
    
    @field_validator('files')
    @classmethod
    def validate_files(cls, v):
        if not v:
            raise ValueError('Files list cannot be empty')
        
        if len(v) > MAX_FILES_PER_REQUEST:
            raise ValueError(f'Too many files requested. Maximum: {MAX_FILES_PER_REQUEST}')
        
        for file_spec in v:
            if '-' not in file_spec:
                raise ValueError(f'Invalid file format: {file_spec}. Expected: database-filehash')
            
            parts = file_spec.split('-', 1)
            if len(parts) != 2:
                raise ValueError(f'Invalid file format: {file_spec}. Expected: database-filehash')
                
            database, file_hash = parts
            
            # Validate database name
            if not database.startswith("experio_cabinet_"):
                raise ValueError(f'Database not allowed: {database}')
            
            # Validate file hash (should be 40 char hex string for SHA-1)
            if len(file_hash) != EXPECTED_HASH_LENGTH:
                raise ValueError(f'Invalid file hash length: {file_hash}')
            
            try:
                int(file_hash, 16)  # Verify it's valid hex
            except ValueError:
                raise ValueError(f'Invalid file hash format: {file_hash}')
                
        return v


class FileInfo(BaseModel):
    """Information about a requested file."""
    database: str
    file_hash: str
    found: bool
    file_size: Optional[int] = None
    error: Optional[str] = None


class FileResponse(BaseModel):
    """Response model for file retrieval."""
    success: bool
    files_found: int
    files_requested: int
    total_size: Optional[int] = None
    file_details: List[FileInfo]


def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)):
    """Verify the authentication token."""
    if credentials.credentials not in VALID_TOKENS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return credentials.credentials


def get_file_path(service: str, database: str, file_hash: str) -> Path:
    """
    Construct the file path based on service, database and file hash.
    
    Args:
        service: Service name (system, app, btblk, decimal, srm, portal)
        database: Database name
        file_hash: File hash (40 character hex string)
    
    Returns:
        Path object for the file
    
    Raises:
        ValueError: If service is not configured
    """
    if service not in SERVICES:
        available_services = ", ".join(SERVICES.keys())
        raise ValueError(f"Service '{service}' not configured. Available services: {available_services}")
    
    filestore_base = SERVICES[service]
    # Get first 2 characters for directory
    folder = file_hash[:2]
    file_path = Path(filestore_base) / database / folder / file_hash
    return file_path

def get_file_metadata(file_path: Path) -> dict:
    """Extract basic metadata from a file."""
    if not file_path.exists():
        return {}
    
    return {
        "file_size": file_path.stat().st_size
    }


@app.get("/health")
async def health():
    """Public health check endpoint - minimal information only."""
    # Check if at least one service is accessible (without exposing details)
    any_service_healthy = False
    for service, path in SERVICES.items():
        if Path(path).exists():
            any_service_healthy = True
            break
    
    return {
        "status": "healthy" if any_service_healthy else "unhealthy",
        "service": "Startgate"
    }


@app.get("/status")
async def detailed_status(token: str = Depends(verify_token)):
    """Authenticated detailed status endpoint for administrators."""
    service_status = {}
    all_healthy = True
    
    for service, path in SERVICES.items():
        path_exists = Path(path).exists()
        service_status[service] = {
            "accessible": path_exists
        }
        if not path_exists:
            all_healthy = False
    
    return {
        "status": "healthy" if all_healthy else "degraded",
        "service": "Startgate File Retrieval Service",
        "configured_services": list(SERVICES.keys()),
        "service_details": service_status,
        "allowed_database_prefix": "experio_cabinet_"
    }


@app.post("/{service}/files")
async def get_files(
    service: str,
    request: FileRequest,
    token: str = Depends(verify_token)
):
    """
    Retrieve multiple files from a specific service filestore.
    
    Args:
        service: Service name (system, app, btblk, decimal, srm, portal)
        request: File request containing list of file specifications
        token: Authentication token
        
    Returns a ZIP file containing all found files, or JSON response with file details.
    """
    # Validate service
    if service not in SERVICES:
        available_services = ", ".join(SERVICES.keys())
        raise HTTPException(
            status_code=400, 
            detail=f"Service '{service}' not configured. Available services: {available_services}"
        )
    
    try:
        file_details = []
        found_files = []
        total_size = 0
        
        # Process each requested file
        for file_spec in request.files:
            try:
                database, file_hash = file_spec.split('-', 1)
                file_path = get_file_path(service, database, file_hash)
                
                # Security check: ensure file is within allowed directory
                service_base = Path(SERVICES[service]).resolve()
                if not str(file_path.resolve()).startswith(str(service_base)):
                    file_details.append(FileInfo(
                        database=database,
                        file_hash=file_hash,
                        found=False,
                        error="Access denied: path traversal detected"
                    ))
                    continue
                
                if file_path.exists():
                    metadata = get_file_metadata(file_path)
                    file_size = metadata.get("file_size", 0)
                    total_size += file_size
                    
                    file_details.append(FileInfo(
                        database=database,
                        file_hash=file_hash,
                        found=True,
                        file_size=file_size
                    ))
                    found_files.append((file_spec, file_path))
                    logger.info(f"Found file in {service}: {file_path} ({file_size} bytes)")
                else:
                    file_details.append(FileInfo(
                        database=database,
                        file_hash=file_hash,
                        found=False,
                        error="File not found"
                    ))
                    logger.warning(f"File not found in {service}: {file_path}")
                    
            except Exception as e:
                file_details.append(FileInfo(
                    database=database if 'database' in locals() else "unknown",
                    file_hash=file_hash if 'file_hash' in locals() else "unknown",
                    found=False,
                    error=f"Error processing file: {str(e)}"
                ))
                logger.error(f"Error processing {file_spec} in {service}: {str(e)}")
        
        # If no files found, return JSON response with details
        if not found_files:
            return FileResponse(
                success=False,
                files_found=0,
                files_requested=len(request.files),
                total_size=0,
                file_details=file_details
            )
        
        # If only one file found and not forcing ZIP, return the file directly
        if len(found_files) == 1 and not request.always_zip:
            file_spec, file_path = found_files[0]
            return StreamingResponse(
                io.BytesIO(file_path.read_bytes()),
                media_type="application/octet-stream",
                headers={"Content-Disposition": f"attachment; filename={file_spec}"}
            )

        # Create ZIP for multiple files or when always_zip is enabled
        zip_buffer = io.BytesIO()
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for file_spec, file_path in found_files:
                zip_file.write(file_path, file_spec)
        
        zip_buffer.seek(0)
        
        return StreamingResponse(
            io.BytesIO(zip_buffer.read()),
            media_type="application/zip",
            headers={"Content-Disposition": f"attachment; filename=startgate_{service}_files.zip"}
        )
        
    except Exception as e:
        logger.error(f"Error in get_files for {service}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=HOST,
        port=PORT,
        reload=False,  # Disabled for production
        log_level=LOG_LEVEL.lower()
    )