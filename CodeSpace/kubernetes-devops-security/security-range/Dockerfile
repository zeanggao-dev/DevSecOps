FROM python:3.11-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY . /app

RUN adduser -D appuser && chown -R appuser:appuser /app

USER appuser

EXPOSE 8080

ENTRYPOINT ["python", "sec-lab.py", "--host", "0.0.0.0", "--port", "8080"]
