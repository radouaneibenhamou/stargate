# Startgate File Retrieval Service

A high-performance FastAPI service that provides direct access to app filestore files, eliminating the 33% overhead of base64 encoding used in traditional JSON APIs. Startgate serves as a gateway to your file repositories with superior performance.

## Overview

Startgate addresses a critical performance bottleneck in app file retrieval by providing direct binary file access instead of base64-encoded JSON responses. It handles files from multiple app databases with automatic ZIP compression for batch requests.

Startgate serves as your efficient gateway to file repositories, ensuring optimal performance and resource utilization.

### Performance Benefits

- **Eliminates 33% base64 overhead**: Direct binary streaming vs base64 encoding
- **ZIP compression**: Additional 35% space savings for multiple files
- **Streaming responses**: Memory-efficient file transfer
- **Multi-database support**: Handles multiple `experio_cabinet_*` databases simultaneously

## Architecture

### File Storage Structure
```
/filestore/
├── experio_cabinet_3/
├── experio_cabinet_4/
├── experio_cabinet_8/
├── experio_cabinet_55/
└── experio_cabinet_70/
    └── {first_2_chars}/
        └── {40_char_sha1_hash}
```

### Technology Stack
- **FastAPI 0.128.0**: Modern async web framework
- **Uvicorn**: High-performance ASGI server
- **Pydantic 2.12.5**: Data validation and serialization
- **Python 3.11**: Latest stable Python runtime

## Features

### Core Functionality
- **Single file retrieval**: Direct binary streaming
- **Multiple file retrieval**: Automatic ZIP archive creation
- **Cross-database access**: Support for multiple app databases
- **Path traversal protection**: Security validation for all file paths
- **File validation**: SHA-1 hash format verification

### Authentication & Security
- **Bearer token authentication**: Secure API access
- **Database prefix validation**: Only `experio_cabinet_*` databases allowed
- **Path traversal prevention**: Validates all file paths within allowed directories
- **Input sanitization**: Comprehensive validation of file specifications

### Response Formats
- **Single file**: Direct binary stream with appropriate headers
- **Multiple files**: ZIP archive with organized file structure
- **Error responses**: Detailed JSON responses for failures
- **Health checks**: Service status and configuration validation

## API Endpoints

### POST /files
Retrieve one or multiple files based on database and file hash specifications.

**Request Format:**
```json
{
  "files": [
    "experio_cabinet_4-06e09b75e7d10f8e669799e4806858b425606c06",
    "experio_cabinet_8-21f389cec886cfe4fb1bae54b78d44b93b1351d9"
  ]
}
```

**Response Types:**
- **Single file**: Binary stream with `Content-Disposition` header
- **Multiple files**: ZIP archive containing all found files
- **No files found**: JSON response with detailed error information

**File Specification Format:**
```
{database}-{file_hash}
```
- `database`: Must start with `experio_cabinet_`
- `file_hash`: 40-character SHA-1 hash (hexadecimal)

### GET /health
Service health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "service": "Startgate File Retrieval Service", 
  "base_path_accessible": true,
  "allowed_database_prefix": "experio_cabinet_"
}
```

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `FILESTORE_BASE_PATH` | Root path to app filestore | - | ✅ |
| `API_TOKEN` | Authentication token for API access | - | ✅ |
| `HOST` | Service bind address | `0.0.0.0` | ❌ |
| `PORT` | Service port number | `8000` | ❌ |
| `LOG_LEVEL` | Logging verbosity | `INFO` | ❌ |
| `MAX_FILES_PER_REQUEST` | Maximum files per batch request | `100` | ❌ |

### Example Configuration (.env)
```env
FILESTORE_BASE_PATH=/ceph/data/k8s-staging-data/odoo/system-fs/filestore
API_TOKEN=your_secure_token_here
MAX_FILES_PER_REQUEST=100
LOG_LEVEL=INFO
```

## Installation & Deployment

### Local Development
```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export FILESTORE_BASE_PATH=/path/to/filestore
export API_TOKEN=your_secure_token

# Run the service
python main.py
```

### Docker Deployment
```bash
# Build and run with Docker Compose
docker-compose up --build

# Service will be available at http://localhost:8000
```

### Docker Features
- **Health checks**: Automated service monitoring
- **Read-only volume mounts**: Secure filestore access
- **Graceful restarts**: `unless-stopped` restart policy
- **Environment-based configuration**: Externalized settings

## Usage Examples

### Authentication
All requests require Bearer token authentication:
```bash
curl -H "Authorization: Bearer your_api_token" \
     -H "Content-Type: application/json" \
     -X POST http://localhost:8000/files \
     -d '{"files": ["experio_cabinet_4-hash123..."]}'
```

### Single File Request
```bash
curl -X POST http://localhost:8000/files \
     -H "Authorization: Bearer token" \
     -H "Content-Type: application/json" \
     -d '{"files": ["experio_cabinet_4-06e09b75e7d10f8e669799e4806858b425606c06"]}' \
     --output downloaded_file.pdf
```

### Multiple Files Request (ZIP)
```bash
curl -X POST http://localhost:8000/files \
     -H "Authorization: Bearer token" \
     -H "Content-Type: application/json" \
     -d @file_list.json \
     --output files_archive.zip
```

### Health Check
```bash
curl http://localhost:8000/health
```

## Testing & Development

### Test Data Generation
The service includes a comprehensive testing script that discovers real files across multiple databases:

```bash
# Generate test file list
python discover_files.py

# Creates test_files_100.json with:
# - 20 files from each of 5 databases
# - Even distribution across folder prefixes
# - Total ~60-70MB of test data
```

### Test Features
- **Multi-database sampling**: Ensures cross-database compatibility
- **Folder distribution**: Tests different SHA-1 hash prefixes
- **Size variety**: Tests files from KB to MB ranges
- **Real data validation**: Uses actual app filestore files

### Performance Testing
```bash
# Test 100 files from multiple databases
curl -X POST http://localhost:8000/files \
     -H "Authorization: Bearer token" \
     -d @test_files_100.json \
     --output performance_test.zip \
     -w "Time: %{time_total}s, Size: %{size_download} bytes"
```

## Validation & Error Handling

### Input Validation
- **File count limits**: Enforced via `MAX_FILES_PER_REQUEST`
- **Database name validation**: Must match `experio_cabinet_*` pattern
- **Hash format validation**: 40-character hexadecimal SHA-1 hashes
- **Path security checks**: Prevents directory traversal attacks

### Error Response Format
```json
{
  "success": false,
  "files_found": 0,
  "files_requested": 2,
  "total_size": 0,
  "file_details": [
    {
      "database": "experio_cabinet_4",
      "file_hash": "invalid_hash",
      "found": false,
      "error": "Invalid file hash length"
    }
  ]
}
```

### HTTP Status Codes
- **200**: Success (file(s) found and returned)
- **401**: Unauthorized (invalid or missing token)
- **422**: Validation Error (invalid request format)
- **500**: Internal Server Error (filesystem or processing issues)

## Security Features

### Access Control
- **Token-based authentication**: All endpoints require valid Bearer token
- **Database access restrictions**: Only `experio_cabinet_*` databases allowed
- **Read-only operations**: Service cannot modify or delete files
- **Path verification**: All file paths validated against base directory

### File System Security
- **Read-only Docker mounts**: Prevents accidental file modifications
- **Path traversal prevention**: Blocks `../` and absolute path attempts
- **Hash validation**: Ensures only valid SHA-1 hashes are processed
- **Error information limits**: Prevents information disclosure in error messages

## Performance Characteristics

### Benchmarks (100 files, 67.5MB total)
- **Processing time**: ~19 seconds
- **Transfer speed**: ~2.3 MB/s average
- **ZIP compression**: 35% size reduction
- **Memory usage**: Streaming responses minimize RAM consumption

### Scalability Features
- **Async processing**: FastAPI async/await for concurrent requests
- **Streaming responses**: Memory-efficient file transfer
- **Configurable limits**: Adjustable batch sizes via environment variables
- **Health monitoring**: Built-in health checks for load balancer integration

## Integration with Experio Ecosystem

Startgate is designed to integrate with the existing experio-bluejay system as a replacement for base64-encoded file retrieval. The performance benefits make it ideal for:

- **High-volume file downloads**: Bulk document retrieval
- **Mobile applications**: Reduced bandwidth usage
- **API optimization**: Eliminating JSON encoding overhead
- **Microservice architecture**: Dedicated file handling service

## Troubleshooting

### Common Issues
1. **401 Unauthorized**: Verify `API_TOKEN` in headers matches server configuration
2. **File not found**: Check database name format and file hash validity
3. **Path errors**: Ensure `FILESTORE_BASE_PATH` points to correct directory
4. **Health check failures**: Verify filestore path accessibility and permissions

### Logging
The service provides detailed logging for debugging:
```bash
# Enable debug logging
export LOG_LEVEL=DEBUG
python main.py
```

### File Path Debugging
```bash
# Verify file exists manually
ls /ceph/data/infra/odoo/system-fs/filestore/experio_cabinet_4/06/06e09b75e7d10f8e669799e4806858b425606c06
```# stargate
