FROM python:3.11-slim

WORKDIR /app

# Устанавливаем зависимости напрямую — без сборки пакета
RUN pip install --no-cache-dir \
    requests \
    "fastapi>=0.111" \
    "uvicorn[standard]>=0.29" \
    "jinja2>=3.1" \
    "itsdangerous>=2.1" \
    "python-multipart>=0.0.9" \
    "aiofiles>=23.2"

# Копируем исходный код в /app/ngfw_matcher/ — чтобы работал import ngfw_matcher
COPY . /app/ngfw_matcher/

EXPOSE 8080

CMD ["uvicorn", "ngfw_matcher.web.main:app", "--host", "0.0.0.0", "--port", "8080"]
