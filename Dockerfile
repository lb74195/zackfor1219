FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

# 平台一般会注入 PORT；本地 docker run 时也可自行 -e PORT=8000
ENV PORT=8000
EXPOSE 8000

# 使用 FastAPI 入口（同时在应用内挂载 /static），适配大多数云平台
# 说明：这里用 sh -lc 是为了让 --port 能读取平台注入的 $PORT
CMD ["sh", "-lc", "python -m uvicorn api.index:app --host 0.0.0.0 --port ${PORT:-8000}"]

