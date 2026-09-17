FROM python:3.12-slim
WORKDIR /app
ENV BIND_HOST=0.0.0.0
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 lab
COPY . .
USER 10001
CMD ["python", "app.py"]
