FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir boto3

# Copy exporter
COPY compliance_exporter.py /app/

# Create directories
RUN mkdir -p /app/scan-results /app/evidence_store

# Expose port
EXPOSE 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:9090/health || exit 1

# Run exporter
ENTRYPOINT ["python", "compliance_exporter.py"]
CMD ["--port", "9090", "--results-dir", "/app/scan-results"]
