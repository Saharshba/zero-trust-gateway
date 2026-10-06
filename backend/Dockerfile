FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY zta ./zta

# One image, three roles (control plane, gateway, internal service): the
# compose file picks the role with the command. Nothing runs as root.
RUN useradd --system --create-home --uid 10001 zta && chown -R zta:zta /srv
USER zta

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s \
    CMD curl -fsS http://localhost:8000/health || exit 1

CMD ["uvicorn", "zta.control_plane.app:app", "--host", "0.0.0.0", "--port", "8000"]
