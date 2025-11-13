# ReelMind 後端服務

> AI 短影音智能體後端服務 - FastAPI + Google Gemini 2.5 Flash

## 📋 專案簡介

ReelMind 後端服務提供完整的 AI 短影音創作功能，包括：
- 🤖 AI 智能對話與腳本生成
- 💳 ECPay 金流整合
- 🔐 Google OAuth 認證
- 📊 訂閱管理與自動續費
- 💾 長期記憶系統
- 👥 用戶資料管理

## 🚀 快速開始

### 環境要求

- Python 3.11+
- PostgreSQL（生產環境）或 SQLite（開發環境）

### 本地開發

```bash
# 1. 克隆專案
cd ReelMindbackend-main

# 2. 建立虛擬環境
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. 安裝依賴
pip install -r requirements.txt

# 4. 設定環境變數（見下方）
export GEMINI_API_KEY="your_api_key"
export JWT_SECRET="your_jwt_secret"
# ... 其他環境變數

# 5. 啟動服務
uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

### Docker 打包與部署

#### 建構 Docker 映像

```bash
# 在 ReelMindbackend-main 目錄下
docker build -t reelmind-backend:latest .
```

#### 運行容器

```bash
# 使用環境變數檔案
docker run -d \
  --name reelmind-backend \
  -p 8000:8000 \
  --env-file .env \
  reelmind-backend:latest

# 或直接指定環境變數
docker run -d \
  --name reelmind-backend \
  -p 8000:8000 \
  -e GEMINI_API_KEY="your_key" \
  -e JWT_SECRET="your_secret" \
  -e DATABASE_URL="postgresql://..." \
  reelmind-backend:latest
```

#### Docker Compose（推薦）

建立 `docker-compose.yml`：

```yaml
version: '3.8'

services:
  backend:
    build: .
    container_name: reelmind-backend
    ports:
      - "8000:8000"
    environment:
      - GEMINI_API_KEY=${GEMINI_API_KEY}
      - JWT_SECRET=${JWT_SECRET}
      - DATABASE_URL=${DATABASE_URL}
      # ... 其他環境變數
    env_file:
      - .env
    restart: unless-stopped
    volumes:
      - ./data:/app/data  # 持久化資料（SQLite 使用）
```

啟動：

```bash
docker-compose up -d
```

## 🔧 環境變數配置

### 🔴 必須設定（核心功能）

```bash
# AI 模型設定
GEMINI_API_KEY=your_gemini_api_key
GEMINI_MODEL=gemini-2.5-flash  # 可選，預設 gemini-2.5-flash

# OAuth 認證設定
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
OAUTH_REDIRECT_URI=https://your-backend.com/api/auth/google/callback
FRONTEND_BASE_URL=https://your-frontend.com
FRONTEND_URL=https://your-frontend.com  # CORS 用

# JWT 與安全設定
JWT_SECRET=your_jwt_secret  # 必須是固定值！
LLM_KEY_ENCRYPTION_KEY=your_32byte_base64_key  # BYOK 加密金鑰
```

### 🟡 建議設定（功能增強）

```bash
# ECPay 金流設定（生產環境）
ECPAY_MODE=prod  # 或 dev（測試環境）
ECPAY_MERCHANT_ID=your_merchant_id
ECPAY_HASH_KEY=your_hash_key  # ⚠️ 注意：確認沒有前後空格
ECPAY_HASH_IV=your_hash_iv   # ⚠️ 注意：確認沒有前後空格，注意容易混淆的字元（0 vs O, 1 vs l）
ECPAY_API=https://payment.ecpay.com.tw/Cashier/AioCheckOut/V5  # 生產環境
# ECPAY_API=https://payment-stage.ecpay.com.tw/Cashier/AioCheckOut/V5  # 測試環境
ECPAY_RETURN_URL=https://your-frontend.com/payment-result.html
ECPAY_NOTIFY_URL=https://your-backend.com/api/payment/webhook
BACKEND_BASE_URL=https://your-backend.com  # 用於構建 ReturnURL
CLIENT_BACK_URL=https://your-frontend.com/payment-result.html  # 取消付款返回頁
ECPAY_IP_WHITELIST=210.200.4.0/24,210.200.5.0/24  # ECPay 伺服器 IP 白名單

# Email 設定（自動續費通知）
SMTP_ENABLED=true
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=your_email@example.com
SMTP_PASSWORD=your_password
CONTACT_EMAIL=your_email@example.com

# 連結授權設定（PPA/n8n 通路）
WEBHOOK_SECRET=your_webhook_secret_key  # ⚠️ 必須設定，用於驗證 PPA/n8n 請求
FRONTEND_URL=https://your-frontend.com  # 用於生成授權連結

# 定時任務安全密鑰（可選）
CRON_SECRET=your_cron_secret
```

### 🟢 可選設定

```bash
# 資料庫設定
DATABASE_URL=postgresql://user:password@host:port/dbname  # PostgreSQL
DATABASE_PATH=/persistent  # SQLite 持久化路徑（Zeabur 使用）

# 管理員設定
ADMIN_USER_IDS=user_id_1,user_id_2  # 管理員用戶 ID 白名單（逗號分隔）

# 知識庫設定
KB_PATH=/app/data/kb.txt
```

## 📦 專案結構

```
ReelMindbackend-main/
├── app.py                    # 主要應用程式
├── memory.py                 # 短期記憶系統
├── prompt_builder.py         # 提示詞構建
├── db_admin.py              # 資料庫管理工具
├── requirements.txt          # Python 依賴套件
├── Dockerfile                # Docker 配置
├── data/
│   └── kb.txt               # 知識庫檔案
├── *.md                     # 文件檔案
└── README.md                # 本文件
```

## 🔌 API 端點

### 認證相關

- `GET /api/auth/google` - 生成 Google OAuth URL
- `GET /api/auth/google/callback` - OAuth 回調處理
- `POST /api/auth/refresh` - 刷新 access token
- `GET /api/auth/me` - 獲取當前用戶資訊

### AI 功能

- `POST /api/chat/stream` - SSE 聊天串流
- `POST /api/generate/positioning` - 一鍵生成帳號定位
- `POST /api/generate/topics` - 一鍵生成選題推薦
- `POST /api/generate/script` - 一鍵生成短影音腳本

### 訂閱與付款

- `POST /api/payment/checkout` - 建立訂單並返回付款表單（需登入）
- `POST /api/payment/create-order` - 建立訂單（新端點，與 checkout 相同）
- `POST /api/payment/webhook` - ECPay 伺服器端通知（自動啟用授權）
- `POST /api/payment/return-url` - ECPay ReturnURL（後端 API）
- `GET /api/payment/return` - 用戶返回頁（前端重定向）
- `GET /api/payment/test-checkmac` - 測試 CheckMacValue 生成（診斷用）
- `GET /api/user/subscription` - 獲取訂閱狀態
- `PUT /api/user/subscription/auto-renew` - 更新自動續費狀態

### 連結授權（PPA/n8n 通路）

- `POST /api/webhook/verify-license` - 接收 PPA/n8n 授權通知，生成授權連結
- `GET /api/user/license/verify` - 驗證授權連結並啟用訂閱（用戶點擊連結時）

### 自動續費

- `POST /api/cron/check-renewals` - 檢查並建立續費訂單（定時任務）

### 用戶資料

- `GET /api/user/conversations/{user_id}` - 獲取對話記錄
- `GET /api/user/generations/{user_id}` - 獲取生成記錄
- `GET /api/user/scripts/{user_id}` - 獲取腳本記錄
- `GET /api/user/memory/{user_id}` - 獲取用戶記憶

### 管理員 API

- `GET /api/admin/users` - 獲取所有用戶
- `GET /api/admin/statistics` - 獲取系統統計
- `GET /api/admin/orders` - 獲取訂單列表
- `PUT /api/admin/users/{user_id}/subscription` - 更新用戶訂閱狀態

完整 API 文檔請參考 `專案更新日誌.md`。

## 🗄️ 資料庫

### 支援的資料庫

- **PostgreSQL**（生產環境推薦）
- **SQLite**（開發環境）

系統會自動檢測 `DATABASE_URL` 環境變數，如果存在則使用 PostgreSQL，否則使用 SQLite。

### 資料庫初始化

首次啟動時會自動初始化資料庫表結構，包括：

- `user_auth` - 用戶認證資訊
- `user_profiles` - 用戶資料
- `licenses` - 訂閱授權
- `orders` - 訂單記錄
- `conversation_summaries` - 對話摘要
- `user_scripts` - 用戶腳本
- `long_term_memory` - 長期記憶
- 等等...

## 🚢 部署到 Zeabur

1. 將專案推送到 GitHub
2. 在 Zeabur 建立新專案
3. 連接 GitHub 倉庫
4. 設定環境變數（見上方環境變數配置）
5. 部署服務

### Zeabur 環境變數設定

在 Zeabur 後台設定以下環境變數：

```bash
GEMINI_API_KEY=...
JWT_SECRET=...
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
OAUTH_REDIRECT_URI=https://your-backend.zeabur.app/api/auth/google/callback
FRONTEND_BASE_URL=https://your-frontend.zeabur.app
# ... 其他環境變數
```

### 定時任務設定

在 Zeabur 設定 Cron Job：

- **URL**：`https://your-backend.zeabur.app/api/cron/check-renewals`
- **方法**：`POST`
- **頻率**：每天 10:00（建議）
- **Headers**（可選）：
  - `X-Cron-Secret: your_cron_secret`

詳細設定請參考 `自動續費定時任務設定指南.md`。

## 📝 重要更新記錄

### 2025-11-13 - ECPay 付款流程完善與日誌優化

- ✅ CheckMacValue 生成邏輯完善（UTF-8 編碼處理、URL 編碼驗證）
- ✅ 日誌級別優化（成功訊息使用 INFO，錯誤訊息使用 ERROR）
- ✅ Webhook 授權流程完善（付款成功後自動啟用用戶授權）
- ✅ 環境變數驗證與錯誤處理增強

### 2025-11-11 - 訂閱付款流程優化與自動續費功能

- ✅ 強制登入才能訂閱付款
- ✅ 取消自動續費功能
- ✅ 自動續費定時任務實作
- ✅ ECPay 付款方式優化

詳細記錄請參考 `2025-11-11更新日誌.md`。

### 2025-11-03 - 後端認證系統全面加固

- ✅ 管理員認證系統
- ✅ 用戶資料權限保護
- ✅ 所有敏感 API 端點加入認證

詳細記錄請參考 `專案更新日誌.md`。

## 💳 付款與授權流程

### 完整流程說明

1. **用戶發起付款**
   - 用戶在前端選擇方案（月費/年費）
   - 前端調用 `POST /api/payment/checkout`（需登入）
   - 後端生成訂單並返回 ECPay 付款表單

2. **ECPay 付款**
   - 用戶在 ECPay 頁面完成付款
   - ECPay 驗證 CheckMacValue 簽章

3. **Webhook 通知（自動授權）**
   - ECPay 發送 Webhook 到 `/api/payment/webhook`
   - 後端驗證簽章和 IP 白名單
   - **付款成功時自動執行**：
     - 更新 `orders` 表狀態為 `paid`
     - 在 `licenses` 表建立/更新授權記錄（`status='active'`）
     - 更新 `user_auth` 表的 `is_subscribed=1`
     - 計算到期日（月費 30 天，年費 365 天）

4. **用戶查詢授權狀態**
   - 調用 `GET /api/user/subscription`
   - 返回 `is_subscribed`、`tier`、`expires_at` 等資訊

### 測試授權流程

- **ECPay 付款授權**：詳細測試步驟請參考 `ECPay付款授權測試指南.md`
- **連結授權（PPA/n8n）**：詳細測試步驟請參考 `連結授權測試指南.md`

## 📚 相關文件

- `2025-11-11更新日誌.md` - 最新更新記錄
- `專案更新日誌.md` - 完整更新歷史
- `ECPay後端檢查報告_綠界客服建議.md` - CheckMacValue 檢查報告
- `ECPay金流配置指南.md` - ECPay 設定說明
- `ECPay_Webhook設定指南.md` - Webhook 設定步驟
- `ECPay付款流程測試指南.md` - 測試環境設定
- `ECPay付款錯誤排查指南.md` - 常見錯誤解決
- `ECPay付款授權測試指南.md` - ECPay 付款授權流程測試步驟
- `連結授權測試指南.md` - PPA/n8n 連結授權流程測試步驟
- `ECPay自動續費方案說明.md` - 自動續費方案比較
- `自動續費定時任務設定指南.md` - 定時任務設定
- `MD檔案整理報告.md` - 文件整理說明

## 🐛 常見問題

### Q: 遇到 "externally-managed-environment" 錯誤？

A: 這是 macOS 系統保護機制，請使用虛擬環境：

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Q: 資料庫連接失敗？

A: 檢查：
1. `DATABASE_URL` 環境變數是否正確設定
2. PostgreSQL 服務是否正常運行
3. 連線字串格式是否正確

### Q: JWT token 失效？

A: 確保 `JWT_SECRET` 環境變數是固定值，不要每次重啟都改變。

### Q: ECPay 付款錯誤？

A: 參考 `ECPay付款錯誤排查指南.md`，檢查：
1. `ChoosePayment` 參數設定
2. ECPay 後台付款方式是否已開通
3. 測試環境和生產環境的設定是否一致

## 🔒 安全注意事項

1. **JWT_SECRET**：必須是固定值，建議使用強隨機字串
2. **LLM_KEY_ENCRYPTION_KEY**：必須是 32 字節的 base64 編碼字串
3. **環境變數**：不要在程式碼中硬編碼敏感資訊
4. **HTTPS**：生產環境必須使用 HTTPS
5. **CORS**：正確設定 `FRONTEND_URL` 避免跨域問題

## 📄 授權

2025 AIJob學院版權所有

---

**最後更新**：2025-11-13
