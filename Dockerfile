FROM python:3.13-slim-bookworm

WORKDIR /app

# Copy requirements file first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY proxy.py .

ENTRYPOINT ["python3", "proxy.py"]
