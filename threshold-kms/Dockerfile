FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN useradd -m -u 1000 kmsuser && mkdir -p /app/data /app/certs && chown -R kmsuser:kmsuser /app
COPY --chown=kmsuser:kmsuser src/ ./src/

ENV PYTHONPATH=/app/src
ENV DOCKER=1
ENV NODE_HOST=0.0.0.0

USER kmsuser

# Запускаем узел (mTLS обязателен: без сертификатов процесс завершится с ошибкой)
CMD ["python", "src/node.py"]
