FROM python:3.13-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8

RUN apt-get update \
    && apt-get install -y --no-install-recommends tshark \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY PufferRelay ./PufferRelay
RUN pip install --no-cache-dir .

# Analysis is passive; mount captures read-only and keep exports on the host.
VOLUME ["/captures", "/out"]
ENTRYPOINT ["pufferrelay"]
CMD ["--help"]
