FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir prometheus-client

# Copy exporter script
COPY compliance_exporter.py /app/

# Create scan results directory
RUN mkdir -p /app/scan-results

# Expose metrics port
EXPOSE 9090

# Run exporter
ENTRYPOINT ["python", "compliance_exporter.py"]
CMD ["--port", "9090", "--results-dir", "/app/scan-results"]
