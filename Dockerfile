# Статическая сборка Tailwind CSS — без CDN-рантайма в браузере
FROM node:20-slim AS assets

WORKDIR /build
COPY package.json tailwind.config.js ./
COPY web/templates ./web/templates
COPY web/static/css/input.css ./web/static/css/input.css
RUN npm install --no-audit --no-fund && \
    npx tailwindcss -i web/static/css/input.css -o web/static/css/tailwind.css --minify


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
COPY --from=assets /build/web/static/css/tailwind.css /app/ngfw_matcher/web/static/css/tailwind.css

EXPOSE 8080

CMD ["uvicorn", "ngfw_matcher.web.main:app", "--host", "0.0.0.0", "--port", "8080"]
