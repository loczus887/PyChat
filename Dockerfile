FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pcs/ pcs/
COPY server/ server/
COPY db/ db/
COPY client/ client/
COPY add_user.py run_client.py ./
COPY scripts/ scripts/

RUN mkdir -p /app/data/certs /app/data/logs

ENV PYCHAT_DATA_DIR=/app/data \
    PYCHAT_HOST=0.0.0.0 \
    PYCHAT_PORT=9000 \
    PYCHAT_LOG_LEVEL=INFO \
    PYCHAT_LOG_FILE=/app/data/logs/pychat.log \
    PYCHAT_DEMO_USER=alice \
    PYCHAT_DEMO_PASSWORD=secret

EXPOSE 9000

VOLUME ["/app/data"]

CMD ["python", "scripts/docker_entrypoint.py"]
