FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install uvicorn starlette aiohttp

# Copy application
COPY bugxhunter_server.py .
COPY config.json .

# Expose port
EXPOSE 7080

# Set default environment
ENV AUTH_TOKEN=""
ENV ALLOW_UNAUTHENTICATED=0
ENV BIND_HOST=0.0.0.0
ENV BIND_PORT=7080

# Health check
HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:7080/health || exit 1

# Run
CMD ["python3", "-m", "uvicorn", "bugxhunter_server:app", "--host", "0.0.0.0", "--port", "7080"]
