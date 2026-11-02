FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --gid 10001 sentinel \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin sentinel \
    && mkdir -p /app/data \
    && touch /app/data/banned_ips.txt \
    && chown -R sentinel:sentinel /app/data

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copier tous les fichiers python en lecture seule pour le processus
COPY --chown=root:root *.py ./

USER sentinel
CMD ["python", "-u", "sentinel.py"]
