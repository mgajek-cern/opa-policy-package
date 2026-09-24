FROM python:3.12-slim AS build
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim
# Runs unprivileged: the service holds no state and needs no write access.
RUN useradd --system --uid 10001 authz
COPY --from=build /install /usr/local
USER 10001
EXPOSE 8000
CMD ["uvicorn", "authz_service.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
