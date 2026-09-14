FROM secureintelligent/acp:latest
WORKDIR /app
COPY app/ .
COPY ca.crt /tmp/build-ca.crt
RUN SSL_CERT_FILE=/tmp/build-ca.crt UV_NATIVE_TLS=1 /app/.venv/bin/uv pip install --python /app/.venv/bin/python . && rm -f /tmp/build-ca.crt
EXPOSE 8000
