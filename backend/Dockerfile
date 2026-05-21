FROM python:3.11-slim

WORKDIR /app

# Install dependencies first so this layer is cached independently of app code.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source (overridden at runtime by a volume mount in Docker
# Compose, but present for standalone image builds and CI).
COPY . .

EXPOSE 8000

# Default: production-style start.
# Docker Compose overrides this with --reload for development.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
