# One image, three roles (centre | edge | provider). The role is chosen by the container command.
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN useradd --create-home --uid 10001 ai2ai
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY ai2ai_platform ./ai2ai_platform
COPY migrations ./migrations
COPY migrations_edge ./migrations_edge
COPY alembic.ini ./
USER ai2ai
# Data (keys, secrets) lives in a mounted volume, never in the image.
ENV AI2AI_DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 8800 8810
CMD ["python", "-m", "ai2ai_platform.cli", "serve-centre", "--port", "8800"]
