# Use the official Python image from the Docker Hub as the base image.
# Build from sre-agent/: docker build -f sandbox-router/Dockerfile .
FROM python:3.13-slim

WORKDIR /app

COPY sandbox-router/requirements.txt .

RUN pip install --no-cache-dir --require-hashes -r requirements.txt

COPY sandbox-router/sandbox_router.py agent_api_auth.py ./

RUN chown -R 1000:1000 /app
USER 1000

EXPOSE 8080

CMD ["uvicorn", "sandbox_router:app", "--host", "0.0.0.0", "--port", "8080"]
