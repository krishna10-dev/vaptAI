FROM python:3.13-slim

ARG NUCLEI_VERSION=3.3.7

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    whois \
    wget \
    unzip \
    ca-certificates \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

RUN wget -qO /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    && unzip /tmp/nuclei.zip -d /usr/local/bin \
    && chmod +x /usr/local/bin/nuclei \
    && rm -f /tmp/nuclei.zip

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY backend /app/backend
WORKDIR /app/backend

ENV PYTHONUNBUFFERED=1
ENV NUCLEI_TEMPLATES_DIRECTORY=/root/nuclei-templates

RUN nmap --version && nuclei -version && (nuclei -ut || true)

EXPOSE 10000

# Refresh templates on boot (non-fatal) and start API server.
CMD ["sh", "-c", "timeout 60 nuclei -ut || true; gunicorn app:app --bind 0.0.0.0:${PORT:-10000} --workers 1 --threads 8 --timeout 180"]
