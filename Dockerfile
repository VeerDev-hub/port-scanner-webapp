FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=5000 \
    DEBUG=false

WORKDIR /app

# No system packages needed: the engine crafts packets itself and never shells
# out to ping/traceroute.
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

EXPOSE 5000

# One worker, many threads: the engine uses threads internally and SSE streams
# need a threaded server. The container runs as root so raw-socket (SYN/stealth)
# scans work on Linux; see docker-compose.yml for NET_RAW/NET_ADMIN.
CMD ["gunicorn", "-w", "1", "-k", "gthread", "--threads", "16", "--timeout", "0", "-b", "0.0.0.0:5000", "app:app"]
