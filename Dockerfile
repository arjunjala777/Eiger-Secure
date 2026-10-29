FROM python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70
ENV PYTHONUNBUFFERED=1 UV_LINK_MODE=copy UV_NO_CACHE=1 HOME=/home/eiger HALCYON_MODE=secure HALCYON_PROFILE=lab
WORKDIR /app
RUN pip install --no-cache-dir uv==0.12.5
COPY pyproject.toml uv.lock LICENSE ./
# Keep dependency installation cached independently of application source.
RUN uv sync --frozen --no-dev --extra blue-team --no-install-project
COPY halcyon ./halcyon
COPY scripts ./scripts
COPY schemas ./schemas
COPY mcp.json ./mcp.json
RUN uv sync --frozen --no-dev --extra blue-team
RUN useradd --uid 10001 --create-home eiger && mkdir -p /app/logs /app/config /app/data && chown eiger:eiger /app/logs /app/config /app/data /home/eiger
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=45s --retries=3 CMD ["/app/.venv/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).read()"]
CMD ["/app/.venv/bin/uvicorn", "halcyon.main:app", "--host", "0.0.0.0", "--port", "8000"]
