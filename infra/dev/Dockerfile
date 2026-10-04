FROM python:3.12-slim
WORKDIR /app
# Locked dependencies first (audit F23): reproducible layer, then the package
# itself with --no-deps so the lock is the only resolution graph.
COPY pyproject.toml requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock
COPY . .
RUN pip install --no-cache-dir --no-deps -e .
EXPOSE 8000
