FROM ghcr.io/astral-sh/uv:0.13.4 AS uv

FROM python:3.12-slim

COPY --from=uv /uv /uvx /bin/
WORKDIR /app

COPY pyproject.toml uv.lock README.md LICENSE alembic.ini ./
COPY src/ ./src/

RUN uv sync --locked --no-dev --no-editable
RUN useradd --create-home --uid 10001 mcp
RUN chown -R mcp:mcp /app

USER mcp
ENV PATH="/app/.venv/bin:${PATH}" \
    MONYNHA_MCP_MODE="http" \
    MONYNHA_MCP_HTTP_HOST="0.0.0.0"

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"

CMD ["monynha-odoo-mcp"]
