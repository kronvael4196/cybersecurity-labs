FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd -u 10001 -m lab && mkdir /app/data /app/logs && chown lab /app/data /app/logs
COPY honeypot.py geo_enricher.py ./
USER 10001
EXPOSE 2222
CMD ["python", "-u", "honeypot.py"]
