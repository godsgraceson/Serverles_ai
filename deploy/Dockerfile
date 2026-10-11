FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV SAS_MODEL_PATH=/app/artifacts/model.pkl
USER nobody
CMD ["python", "scripts/run_local.py"]
