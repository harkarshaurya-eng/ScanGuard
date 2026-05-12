FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsutils \
    nmap \
    netcat-openbsd \
    whois \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE ./
COPY scanguard ./scanguard
COPY examples ./examples

RUN python -m pip install --upgrade pip && python -m pip install .

ENTRYPOINT ["scanguard"]


