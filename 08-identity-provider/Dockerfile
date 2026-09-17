FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd -u 10001 -m lab && mkdir /app/data && chown lab /app/data
COPY auth_server.py middleware.py ./
USER 10001
EXPOSE 8001
CMD ["uvicorn", "auth_server:create_app", "--factory", "--host", "0.0.0.0", "--port", "8001", "--workers", "1"]
