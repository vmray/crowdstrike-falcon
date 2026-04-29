# Use slim variant to reduce image size
FROM python:3.10-slim

# Prevent .pyc files and enable unbuffered stdout/stderr for logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies in a separate layer so it is cached unless requirements change
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY app/ .

# Run as non-root user for security
RUN useradd --no-create-home --shell /bin/false connector

# Permanent volume for log output
VOLUME /app/log

COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
