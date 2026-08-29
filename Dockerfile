# syntax=docker/dockerfile:1
# Multi-stage build for a small, reproducible image that runs the Warden CLI.

FROM python:3.12-slim AS builder
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --upgrade pip build \
 && pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.12-slim AS runtime
# Run as a non-root user.
RUN useradd --create-home --uid 10001 warden
WORKDIR /home/warden
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels
USER warden

# Offline by default so `docker run <image>` works with no API key.
ENV WARDEN_FAKE_LLM=1
ENTRYPOINT ["warden"]
CMD ["eval"]

# Examples:
#   docker build -t warden .
#   docker run --rm warden eval
#   docker run --rm warden governed --fake
#   docker run --rm -e WARDEN_FAKE_LLM=0 -e OPENAI_API_KEY=sk-... warden governed
