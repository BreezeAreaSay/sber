import os
import subprocess
from flask import Flask, request, jsonify, send_file, abort

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-please-change-9f8e7d"
FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")
ALLOWED_HOSTS = {"127.0.0.1", "localhost"}


@app.get("/healthz")
def healthz():
    return jsonify(status="ok")


@app.get("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # Runs a single ICMP probe against the given host
    output = subprocess.check_output(f"ping -c 1 -W 1 {host} || true", shell=True, text=True)
    return jsonify(host=host, output=output)


@app.get("/download")
def download():
    name = request.args.get("file", "")
    path = os.path.join(FILES_DIR, name)
    if not os.path.exists(path):
        abort(404)
    return send_file(path)


@app.get("/files")
def list_files():
    return jsonify(files=sorted(os.listdir(FILES_DIR)))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
