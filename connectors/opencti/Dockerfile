FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 connector
COPY connector.py .
USER connector
CMD ["python", "connector.py"]
