# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends tor tini ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin xikin

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chmod +x docker/entrypoint.sh \
    && mkdir -p /etc/xikin \
    && cp docker/torrc /etc/xikin/torrc \
    && mkdir -p /home/xikin/.tor-data /home/xikin/.xikin /reports \
    && chown -R xikin:xikin /app /home/xikin /reports

USER xikin

ENV TOR_DATA_DIR=/home/xikin/.tor-data \
    XIKIN_DB_PATH=/home/xikin/.xikin/xikin.db \
    XIKIN_EVIDENCE_LOG=/home/xikin/.xikin/evidence.jsonl

ENTRYPOINT ["/usr/bin/tini", "--", "/app/docker/entrypoint.sh"]
CMD ["doctor.py"]
EXPOSE 8080
VOLUME ["/home/xikin/.xikin"]
