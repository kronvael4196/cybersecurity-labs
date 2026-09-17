FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends iptables && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd -u 10001 -m lab && mkdir /app/data && chown lab /app/data
COPY app.py actions.py ./
USER 10001
EXPOSE 8080
CMD ["uvicorn", "app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
