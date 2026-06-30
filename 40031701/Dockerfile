FROM python:3.12-slim

WORKDIR /app
RUN mkdir -p /data

COPY pyproject.toml README.md ./
COPY src ./src

ENV PYTHONPATH=/app/src
EXPOSE 8080

ENTRYPOINT ["python", "-m", "secure_messenger", "server", "--host", "0.0.0.0", "--port", "8080", "--db", "/data/messenger.db"]

