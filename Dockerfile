FROM python:3.11-slim

WORKDIR /app

# 複製需求檔案
COPY requirements.txt .

# 安裝依賴
RUN pip install --no-cache-dir -r requirements.txt

# 複製應用程式檔案
COPY . .

# 建立 data 目錄並複製知識庫（如果存在的話）
RUN mkdir -p /app/data

# 暴露端口
EXPOSE 3000

# 啟動命令
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "3000"]
