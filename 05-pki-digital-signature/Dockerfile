FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 pki \
    && mkdir /app/data /app/tls && chown pki:pki /app/data /app/tls
COPY . .
USER 10001
CMD ["python", "app.py"]
