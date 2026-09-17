FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server sshpass \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash analyst \
    && mkdir -p /run/sshd /logs /etc/ssh/keys
COPY sshd_config /etc/ssh/sshd_config
COPY collector.py /app/collector.py
COPY demo.py /app/demo.py
EXPOSE 22
CMD ["python", "-u", "/app/collector.py"]
