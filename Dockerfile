FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --retries 10 --timeout 60 -r requirements.txt
COPY src/ ./src/
ENV PYTHONPATH=/app/src PYTHONUNBUFFERED=1
USER 65534
EXPOSE 8080
CMD ["python", "-m", "orchestrator.app"]
