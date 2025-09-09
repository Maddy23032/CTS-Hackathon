# Dockerfile (crawler service)

FROM mcr.microsoft.com/playwright/python:v1.46.0-jammy

WORKDIR /app

# Install Python deps
COPY requirements.txt .

# Install deps + playwright package
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install playwright \
    && playwright install --with-deps

# Copy your source code
COPY . .

EXPOSE 8001

CMD ["uvicorn", "crawler_api:app", "--host", "0.0.0.0", "--port", "8001"]
