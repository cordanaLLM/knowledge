# kb-mcp — tiny FastMCP SSE/HTTP server over the Open WebUI knowledge base.
# Build + push to home Harbor (LAN pulls), then digest-pin in values.yaml.
FROM python:3.14-slim@sha256:cad9a2c871761c413caa6fdd6441c783451e740a48aaeba60ae62a8b53525ef6

# This manifest owns the exact Python dependency closure. The versions match
# the deployed digest recorded in values.yaml.
COPY files/requirements.lock /app/requirements.lock
RUN pip install --no-cache-dir --root-user-action=ignore \
    --requirement /app/requirements.lock \
    && pip check

# Non-root uid 1000 (matches the pod securityContext runAsUser).
RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin app

COPY files/server.py files/mcpo_proxy.py files/test_mcpo_proxy.py files/test_server_tools.py /app/

# Validate the proxy guards and the exported FastMCP tool surface in the same
# dependency environment that will run in-cluster, then omit tests at runtime.
RUN PYTHONWARNINGS=error python3 -m unittest discover -s /app -p 'test_*.py' \
    && rm /app/test_mcpo_proxy.py /app/test_server_tools.py

USER 1000
WORKDIR /app
EXPOSE 8000
ENTRYPOINT ["python3", "-u", "/app/server.py"]
