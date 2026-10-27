FROM node:22-alpine AS frontend
WORKDIR /frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.13-slim
WORKDIR /app
COPY requirements*.txt ./
RUN pip install --no-cache-dir -r requirements.txt -c requirements.lock.txt
COPY backend/ backend/
COPY migrations/ migrations/
COPY alembic.ini ./
COPY --from=frontend /frontend/dist frontend/dist
RUN useradd --uid 10001 --create-home cybertwin && mkdir data && chown cybertwin:cybertwin data
USER cybertwin
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
