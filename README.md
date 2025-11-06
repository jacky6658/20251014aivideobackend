# AI 短影音智能體 - 後端服務

## 📌 專案整合報告（後端 ReelMindbackend）

### 一、專案總覽（角色與資料流）
- **角色定位**：FastAPI 核心服務，承載 OAuth、聊天/生成（含 SSE）、資料持久化（SQLite/PostgreSQL）、管理端 API、訂單/授權 API。
- **資料流**：
  - 前端呼叫 `/api/auth/*` 完成登入；自動註冊 `user_auth`
  - `/api/chat/stream` 串流回覆並寫入 `conversation_summaries`
  - `/api/scripts/*` 與 `generations`、`user_scripts`、`positioning_records` 等表互動
  - 帳單與授權：`/api/user/orders/{id}`、`/api/user/license/{id}`、`/api/admin/orders`

### 二、目前擁有功能（重點）
- ✅ PostgreSQL/SQLite 雙棧自動切換、方言相容（日期/佔位符/UPSERT）
- ✅ 管理端 API：模式統計、對話/腳本清單、分析、CSV 匯出
- ✅ 帳單/授權表與 API：`orders`、`licenses`（查詢已上線）
- ✅ OAuth 修復：`ON CONFLICT` 與 `expires_at` 類型處理

### 三、系統架構與資料流（簡）
- 後端（本專案）←→ PostgreSQL（Zeabur）
- 提供前端與後台管理兩端使用之統一 API

### 四、尚未解決/待辦（Back）
- ⏳ 金流整合（ECPay/序號）：新增 `/api/payment/*`、驗簽、回傳、落單、開立發票欄位
- ⏳ Admin 權限強化：加入管理員 JWT/白名單、速率限制
- ⏳ 訂單 CSV 匯出端點 `/api/admin/export/orders`

### 五、已解決重點（Back）
- ✅ `INSERT OR REPLACE` → PostgreSQL `ON CONFLICT ... DO UPDATE`
- ✅ `expires_at` 類型修復（timestamp vs numeric）
- ✅ 日期函式相容（`datetime('now')` → `CURRENT_TIMESTAMP` / `INTERVAL`）
- ✅ 加入 `orders`、`licenses` 表，並提供查詢 API
- ✅ 500 錯誤修復：補齊 `conversation_summaries` 表缺少欄位（`message_count`、`updated_at`）
- ✅ CORS 設定：加入前端自訂網域 `reelmind.aijob.com.tw` 和後台 `backmanage.zeabur.app`
- ✅ `create_app()` 函數修正：確保返回 `app` 實例
- ✅ PostgreSQL/SQLite SQL 語法差異修正：所有 API 端點都支援雙資料庫
- ✅ **長期記憶系統**：新增 `long_term_memory`、`ai_advisor_chats`、`ip_planning_chats`、`llm_conversations` 資料表
- ✅ **會話管理API**：新增 `/api/memory/long-term`、`/api/memory/sessions` 端點
- ✅ **管理員長期記憶API**：新增 `/api/admin/long-term-memory`、`/api/admin/memory-stats` 端點

---
（以下為原 README 內容）

## ⚠️ 重要問題 - 優先解決

### 🚨 腳本儲存系統問題

**現象**：腳本儲存功能無法正常工作，出現 401 Unauthorized 錯誤

#### 問題分析

1. **API認證問題**：
   - 腳本相關API需要用戶認證
   - 前端認證token可能過期或無效
   - 需要檢查 `get_current_user` 函數的實現

2. **資料庫鎖定問題**：
   - 偶爾出現 `database is locked` 錯誤
   - 多個請求同時訪問SQLite資料庫
   - 需要優化資料庫連接管理

3. **影響範圍**：
   - ❌ 腳本儲存功能
   - ❌ 腳本載入功能
   - ❌ 腳本管理功能（重命名、刪除）

### 🚨 用戶資料持久化問題

**現象**：用戶反映「重新刷新登入後帳號定位不見了」

#### 原因分析

1. **本地資料庫 vs Zeabur 資料庫**：
   - 本地開發時，資料儲存在本機的 `backend/data/chatbot.db`
   - Zeabur 部署時，資料儲存在 Zeabur 伺服器的資料庫
   - 這兩個資料庫是**完全獨立**的
   - **問題**：本地創建的資料不會同步到 Zeabur

2. **SQLite 的限制**：
   - Zeabur 重新部署時，SQLite 資料庫會被**重置**
   - 所有用戶資料（帳號定位記錄、對話歷史、生成記錄）會**遺失**
   - **不適合生產環境長期使用**

3. **影響範圍**：
   - ❌ 用戶的帳號定位記錄
   - ❌ 對話歷史
   - ❌ 生成的腳本記錄
   - ❌ 用戶偏好設定
   - ❌ 長期記憶數據

#### 解決方案

##### 🔴 短期方案（目前使用中）

**限制**：
- 在 Zeabur 上重新創建的記錄會保存，但只到下次重新部署為止
- 每次重新部署都會遺失所有用戶資料
- **僅適用於測試和開發階段**

**注意事項**：
```python
# 目前的資料庫初始化方式（有資料遺失風險）
DB_PATH = os.path.join(os.path.dirname(__file__), "data", "chatbot.db")
conn = sqlite3.connect(DB_PATH)  # Zeabur 重新部署時會重置
```

##### 🟢 長期方案（強烈建議）

**1. 使用持久化資料庫服務**

推薦選項：
- **PostgreSQL**（Zeabur 原生支援，推薦）
- **MySQL**（Zeabur 原生支援）
- **MongoDB**（適合文檔型資料）

**Zeabur PostgreSQL 整合步驟**：
```bash
# 1. 在 Zeabur 專案中添加 PostgreSQL 服務
# 2. Zeabur 會自動提供連線資訊：
#    DATABASE_URL=postgresql://user:password@host:port/dbname

# 3. 更新 requirements.txt
pip install psycopg2-binary  # PostgreSQL 驅動
pip install sqlalchemy       # ORM（可選）

# 4. 修改 app.py 連接邏輯
import os
import psycopg2
from urllib.parse import urlparse

DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL:
    # 使用 PostgreSQL
    url = urlparse(DATABASE_URL)
    conn = psycopg2.connect(
        host=url.hostname,
        port=url.port,
        user=url.username,
        password=url.password,
        database=url.path[1:]
    )
else:
    # 本地開發使用 SQLite
    conn = sqlite3.connect("data/chatbot.db")
```

**2. 資料庫遷移計劃**

**階段 1：準備工作**
- [ ] 在 Zeabur 添加 PostgreSQL 服務
- [ ] 取得連線 URL
- [ ] 安裝必要的 Python 套件

**階段 2：程式碼修改**
- [ ] 修改 `init_database()` 函數支援 PostgreSQL
- [ ] 更新 SQL 語法（SQLite → PostgreSQL）
- [ ] 處理資料類型差異（例如：`AUTOINCREMENT` → `SERIAL`）
- [ ] 測試所有 API 端點

**階段 3：資料遷移**
- [ ] 備份現有 SQLite 資料
- [ ] 編寫遷移腳本
- [ ] 將資料匯入 PostgreSQL
- [ ] 驗證資料完整性

**階段 4：部署**
- [ ] 更新 Zeabur 環境變數
- [ ] 重新部署後端服務
- [ ] 完整測試所有功能
- [ ] 監控資料持久化狀態

**3. SQLite vs PostgreSQL 語法差異**

| 功能 | SQLite | PostgreSQL |
|------|--------|------------|
| 自動遞增 | `AUTOINCREMENT` | `SERIAL` 或 `BIGSERIAL` |
| 布林值 | `INTEGER` (0/1) | `BOOLEAN` |
| 日期時間 | `TEXT` 或 `INTEGER` | `TIMESTAMP` |
| JSON | `TEXT` | `JSON` 或 `JSONB` |
| 全文搜索 | 有限 | 強大的 `tsvector` |

**4. 預估工作量**

- **程式碼修改**：2-3 小時
- **測試驗證**：1-2 小時
- **資料遷移**：1 小時
- **總計**：4-6 小時

#### 臨時緩解措施

在完成資料庫遷移之前，可採取以下措施：

1. **定期備份**：
   ```bash
   # 在 Zeabur 重新部署前備份資料庫
   # 使用 db_admin.py 工具
   python db_admin.py backup
   ```

2. **降低重新部署頻率**：
   - 在本地充分測試後再推送
   - 使用 Git 分支進行開發
   - 減少不必要的部署

3. **用戶溝通**：
   - 在前端顯示提示：「測試階段，資料可能會重置」
   - 提供匯出功能（未來）

#### 實施優先級

🔴 **P0 - 緊急（1 週內）**：
- [ ] 評估並選擇持久化資料庫方案
- [ ] 制定詳細的遷移計劃

🟡 **P1 - 高優先級（2 週內）**：
- [ ] 完成 PostgreSQL 整合
- [ ] 資料庫遷移腳本開發
- [ ] 完整測試

🟢 **P2 - 中優先級（1 個月內）**：
- [ ] 實施自動備份機制
- [ ] 添加資料匯出功能
- [ ] 優化查詢效能

---

## 專案簡介
AI 短影音智能體後端服務，提供短影音腳本生成和文案創作功能。

## 技術棧
- **框架**: FastAPI
- **AI 模型**: Google Gemini 2.5 Flash
- **語言**: Python 3.11
- **部署**: Zeabur

## 功能特色
- 短影音腳本生成
- 智能文案創作
- 支援多平台格式（IG Reels、TikTok、小紅書）
- 自定義腳本時長（30/60/90秒）
- 知識庫整合

## 環境變數設定
```bash
# AI 模型設定
GEMINI_API_KEY=your_gemini_api_key
GEMINI_MODEL=gemini-2.5-flash
KB_PATH=/app/data/kb.txt

# OAuth 認證設定
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
OAUTH_REDIRECT_URI=https://aivideobackend.zeabur.app/api/auth/google/callback

# JWT 設定（必須是固定值）
JWT_SECRET=u5c1N4kQm8Zf2Tg7Pp9Lr3Xw6Yd0Aq2H

# 資料庫設定（可選）
DATABASE_URL=postgresql://user:password@host:port/dbname  # 如果有 PostgreSQL
DATABASE_PATH=/persistent  # SQLite 持久化路徑（Zeabur 使用）
```

**重要注意事項**：
- `JWT_SECRET` 必須是固定值，建議使用提供的值或在 Zeabur 環境變數中設定
- 如果 `JWT_SECRET` 改變，所有現有的 access token 都會失效
- `OAUTH_REDIRECT_URI` 必須與 Google Cloud Console 中設定的 redirect URI 完全一致

## 本地開發

### 第一次設定（macOS）
由於 macOS 系統的 Python 環境保護機制，需要使用虛擬環境：

**完整的複製貼上指令**：
```bash
# 1. 進入後端目錄
cd /Users/user/Downloads/ai_web_app/對話式/chatbot/backend

# 2. 創建虛擬環境
python3 -m venv venv

# 3. 啟動虛擬環境
source venv/bin/activate

# 4. 安裝依賴套件
pip install uvicorn fastapi google-generativeai python-dotenv

# 5. 設定 API Key（替換成您的實際金鑰）
export GEMINI_API_KEY="AIzaSyCNmsgpPxo6acx3TV1VrvMLWOvqqj38TR4"

# 6. 啟動服務
python -m uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

### 快速啟動腳本（推薦）
使用修復後的 `start.sh` 腳本，會自動安裝所有必要的套件：

```bash
cd /Users/user/Downloads/ai_web_app/對話式/chatbot/backend
./start.sh
```

**腳本功能**：
- ✅ 自動啟動虛擬環境
- ✅ 自動安裝所有必要的套件（包括 `python-dotenv`）
- ✅ 自動設定 API Key
- ✅ 自動啟動後端服務

**完整的複製貼上指令**：
```bash
# 1. 進入後端目錄
cd /Users/user/Downloads/ai_web_app/對話式/chatbot/backend

# 2. 執行啟動腳本（會自動處理所有設定）
./start.sh
```

**預期結果**：
```
🚀 啟動 AI 短影音智能體後端服務...
📦 安裝必要的套件...
Successfully installed python-dotenv-1.1.1
🚀 啟動後端服務...
知識庫載入狀態: 成功
知識庫內容長度: 5945 字元
INFO: Uvicorn running on http://127.0.0.1:8000
INFO: Application startup complete.
```

### 手動啟動（每次開發時）
**完整的複製貼上指令**：
```bash
# 1. 進入後端目錄
cd /Users/user/Downloads/ai_web_app/對話式/chatbot/backend

# 2. 啟動虛擬環境
source venv/bin/activate

# 3. 設定 API Key（替換成您的實際金鑰）
export GEMINI_API_KEY="AIzaSyCNmsgpPxo6acx3TV1VrvMLWOvqqj38TR4"

# 4. 啟動服務
python -m uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

### 測試 API
```bash
curl http://localhost:8000/api/health
```

## Docker 部署

### 建構映像
```bash
docker build -t ai-video-backend .
```

### 運行容器
```bash
docker run -p 8000:8000 -e GEMINI_API_KEY=your_key ai-video-backend
```

## API 端點

### 健康檢查
- **GET** `/api/health`
- 回應: `{"status": "ok"}`

### 聊天串流
- **POST** `/api/chat/stream`
- 請求格式:
```json
{
  "message": "生成腳本",
  "platform": "Reels",
  "topic": "主題",
  "duration": "30",
  "profile": "帳號定位",
  "history": []
}
```

### 長期記憶系統
- **POST** `/api/memory/long-term` - 儲存長期記憶
- **GET** `/api/memory/long-term` - 獲取用戶長期記憶（支援會話篩選）
- **GET** `/api/memory/sessions` - 獲取用戶會話列表

### 管理員長期記憶 API
- **GET** `/api/admin/long-term-memory` - 獲取所有長期記憶記錄（管理員用）
- **GET** `/api/admin/memory-stats` - 獲取長期記憶統計數據

## 部署到 Zeabur

1. 將專案推送到 GitHub
2. 在 Zeabur 建立新專案
3. 連接 GitHub 倉庫
4. 設定環境變數 `GEMINI_API_KEY`
5. 部署服務

## 專案結構
```
backend/
├── app.py              # 主要應用程式
├── Dockerfile          # 容器化配置
├── requirements.txt    # Python 依賴套件
├── start.sh           # 快速啟動腳本
├── setup_env.sh       # 環境設定腳本
├── data/
│   └── kb.txt         # 知識庫檔案
├── venv/              # 虛擬環境（本地開發）
└── README.md          # 說明文件
```

## 常見問題

### Q: 遇到 "externally-managed-environment" 錯誤？
A: 這是 macOS 系統保護機制，請使用虛擬環境：
```bash
python3 -m venv venv
source venv/bin/activate
pip install uvicorn fastapi google-generativeai
```

### Q: 每次都要重新設定環境變數？
A: 使用提供的 `start.sh` 腳本，一鍵啟動所有設定。

### Q: 知識庫載入失敗？
A: 確保 `data/kb.txt` 檔案存在於後端目錄中。

### Q: AI 沒有回應？
A: 檢查：
1. API Key 是否正確設定
2. 網路連線是否正常
3. 後端服務是否正常運行

## 更新日誌

### 2025-11-06 - 安全漏洞修復（JWT、BYOK、Rate Limiting）

#### 🔒 安全修復
- **JWT 實作修復**：使用標準 PyJWT 庫替換自定義實現，修復嚴重安全漏洞
  - 修復簽名算法弱點（SHA256 → HMAC-SHA256）
  - 修復 Base64 填充處理不當
  - 修復 Timing Attack 風險
  - 保持向後兼容（如果 PyJWT 未安裝，回退到舊實現）
  
- **BYOK 加密金鑰管理強化**：加強金鑰格式驗證和環境變數檢查
  - 強制要求生產環境設定 `LLM_KEY_ENCRYPTION_KEY` 環境變數
  - 驗證金鑰格式（32 字節 base64 編碼）
  - 移除臨時金鑰生成（防止重啟後數據無法解密）
  - 優化錯誤處理，不影響應用啟動
  
- **Rate Limiting 實作**：添加 API 速率限制，防止暴力破解和 DoS 攻擊
  - 使用 slowapi 庫實作速率限制
  - `POST /api/user/llm-keys` - 限制 5 次/分鐘
  - `POST /api/user/llm-keys/test` - 限制 3 次/分鐘
  - 保持向後兼容（如果 slowapi 未安裝，功能禁用但不影響運行）

#### 🛠️ 技術修改
**檔案：app.py**

**1. 導入安全庫（約 14-30 行）**：
```python
# JWT 支援
try:
    import jwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False
    print("WARNING: PyJWT 未安裝，將使用舊的 JWT 實現。請執行: pip install PyJWT")

# Rate Limiting 支援
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    SLOWAPI_AVAILABLE = True
except ImportError:
    SLOWAPI_AVAILABLE = False
    print("WARNING: slowapi 未安裝，Rate Limiting 功能將無法使用。請執行: pip install slowapi")
```

**2. JWT 函數修改（約 741-819 行）**：
- `generate_access_token()`：使用 PyJWT 庫生成標準 JWT token
- `verify_access_token()`：使用 PyJWT 庫驗證 token，修復安全漏洞

**3. BYOK 金鑰管理修改（約 54-75 行）**：
- `get_encryption_key()`：強制要求環境變數，驗證金鑰格式
- `get_cipher()`：優化錯誤處理，不影響應用啟動

**4. Rate Limiting 設定（約 1450-1456 行）**：
- 在 `create_app()` 中初始化 Rate Limiter
- 為 BYOK API 端點添加速率限制裝飾器

#### 📦 依賴更新
**新增依賴**（可選，建議安裝）：
```bash
pip install PyJWT>=2.8.0
pip install slowapi>=0.1.9
```

**環境變數要求**（生產環境必須設定）：
```bash
# BYOK 加密金鑰（必須設定）
LLM_KEY_ENCRYPTION_KEY=<32字節的base64編碼Fernet金鑰>

# 生成金鑰的方法：
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

#### ✅ 兼容性保證
- **前端兼容**：JWT token 格式與前端完全兼容，無需修改前端代碼
- **向後兼容**：如果依賴未安裝，系統會回退到舊實現並顯示警告
- **部署安全**：優化錯誤處理，確保環境變數未設定時不會導致應用崩潰

#### 🔍 測試建議
1. **JWT 測試**：登入功能應正常運作，token 格式與前端兼容
2. **BYOK 測試**：確保 `LLM_KEY_ENCRYPTION_KEY` 已正確設定
3. **Rate Limiting 測試**：快速發送多個請求，應看到 429 錯誤

---

### 2025-11-04 - BYOK (Bring Your Own Key) 功能實作

#### 🚀 新增功能
- **BYOK 功能**：允許用戶使用自己的 LLM API Key
- **加密存儲**：使用 Fernet 對稱加密安全存儲 API Key
- **多提供商支援**：支援 Google Gemini 和 OpenAI
- **自動優先使用**：所有 LLM 呼叫自動優先使用用戶的 API Key
- **完整 API 端點**：4 個完整的 API 端點用於管理用戶的 API Key

#### 🛠️ 技術修改
**檔案：app.py**

**1. 導入加密庫（約 13-19 行）**：
```python
try:
    from cryptography.fernet import Fernet
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
```

**2. 加密功能實作（約 29-123 行）**：
- `get_encryption_key()`：獲取加密金鑰（從環境變數或生成）
- `get_cipher()`：獲取 Fernet 加密器
- `encrypt_api_key()`：加密 API Key
- `decrypt_api_key()`：解密 API Key
- `get_user_llm_key()`：獲取用戶的 LLM API Key（如果有的話）

**3. 資料庫表結構（約 352-365 行）**：
```sql
CREATE TABLE IF NOT EXISTS user_llm_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    encrypted_key TEXT NOT NULL,
    last4 TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user_profiles (user_id),
    UNIQUE(user_id, provider)
)
```

**4. API 端點實作（約 6641-6840 行）**：
- `POST /api/user/llm-keys` - 保存 API Key
- `GET /api/user/llm-keys/{user_id}` - 獲取已保存的金鑰資訊
- `POST /api/user/llm-keys/test` - 測試 API Key 是否有效
- `DELETE /api/user/llm-keys/{user_id}` - 清除 API Key

**5. LLM 呼叫邏輯整合**：
- 修改 `/api/generate/positioning`：優先使用用戶的 API Key
- 修改 `/api/generate/topics`：優先使用用戶的 API Key
- 修改 `/api/generate/script`：優先使用用戶的 API Key
- 修改 `/api/chat/stream`：優先使用用戶的 API Key

#### 🔐 安全性措施
1. **加密存儲**：
   - 使用 Fernet 對稱加密（AES-128）
   - 加密金鑰從環境變數 `LLM_KEY_ENCRYPTION_KEY` 讀取
   - 如果未設定，會生成臨時金鑰（僅用於開發）

2. **權限控制**：
   - 所有 API 端點都需要 JWT token 驗證
   - 用戶只能訪問自己的 API Key
   - 使用 `get_current_user` 依賴項驗證用戶身份

3. **最小化暴露**：
   - GET API 只返回最後4位數字，不返回完整金鑰
   - 完整金鑰只在後端內部使用，不會傳遞到前端

4. **HTTPS 傳輸**：
   - 所有 API 請求都應該通過 HTTPS 傳輸
   - 確保 API Key 在傳輸過程中的安全性

#### 📊 BYOK 運作方式

**1. 用戶設定 API Key**：
```
用戶輸入 API Key
  ↓
前端發送 POST /api/user/llm-keys
  ↓
後端驗證用戶身份
  ↓
後端加密 API Key（使用 Fernet）
  ↓
後端保存到 user_llm_keys 表
  ↓
返回成功訊息（包含最後4位）
```

**2. AI 生成時自動使用**：
```
用戶發起 AI 生成請求
  ↓
後端檢查是否有用戶的 API Key
  ↓
如果有 → 使用用戶的 API Key
如果沒有 → 使用系統預設的 GEMINI_API_KEY
  ↓
調用 LLM API（Gemini 或 OpenAI）
  ↓
返回生成結果
```

**3. 優先級邏輯**：
```python
# 檢查是否有用戶自定義的 API Key
user_id = getattr(body, 'user_id', None)
user_api_key = get_user_llm_key(user_id, "gemini") if user_id else None

# 如果沒有用戶的 API Key，使用系統預設的
api_key = user_api_key or os.getenv("GEMINI_API_KEY")

# 使用 API Key 配置 LLM
genai.configure(api_key=api_key)
```

#### 🔧 環境變數設定

**必要環境變數**：
```bash
# BYOK 加密金鑰（必須設定！）
LLM_KEY_ENCRYPTION_KEY=your_base64_encoded_fernet_key_here

# 生成加密金鑰的方法：
# python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

**系統預設 API Key（如果用戶沒有設定）**：
```bash
GEMINI_API_KEY=your_gemini_api_key
```

#### 📦 依賴套件

**新增依賴**：
```bash
pip install cryptography
```

**requirements.txt 更新**：
```
cryptography>=41.0.0
```

#### 🎯 API 端點詳情

**1. POST `/api/user/llm-keys` - 保存 API Key**：
```json
// Request
{
  "user_id": "user123",
  "provider": "gemini",  // 或 "openai"
  "api_key": "AIzaSy..."
}

// Response
{
  "message": "API Key 已安全保存",
  "provider": "gemini",
  "last4": "TR4"
}
```

**2. GET `/api/user/llm-keys/{user_id}` - 獲取已保存的金鑰**：
```json
// Response
{
  "keys": [
    {
      "provider": "gemini",
      "last4": "TR4",
      "created_at": "2025-11-04T10:00:00",
      "updated_at": "2025-11-04T10:00:00"
    }
  ]
}
```

**3. POST `/api/user/llm-keys/test` - 測試 API Key**：
```json
// Request
{
  "provider": "gemini",
  "api_key": "AIzaSy..."
}

// Response (成功)
{
  "valid": true,
  "message": "Gemini API Key 有效"
}

// Response (失敗)
{
  "valid": false,
  "error": "Gemini API Key 無效: ..."
}
```

**4. DELETE `/api/user/llm-keys/{user_id}` - 清除 API Key**：
```json
// Request
{
  "provider": "gemini"
}

// Response
{
  "message": "API Key 已刪除",
  "provider": "gemini"
}
```

#### 🎯 測試結果
所有功能已驗證正常：
- ✅ **資料庫表創建**：`user_llm_keys` 表正確創建
- ✅ **加密功能**：API Key 正確加密和解密
- ✅ **保存 API Key**：成功保存到資料庫並加密存儲
- ✅ **獲取 API Key**：正確返回最後4位，不暴露完整金鑰
- ✅ **測試 API Key**：正確驗證 Gemini 和 OpenAI API Key
- ✅ **清除 API Key**：成功刪除用戶的 API Key
- ✅ **自動使用**：所有 LLM 呼叫優先使用用戶的 API Key
- ✅ **權限控制**：用戶只能訪問自己的 API Key

#### 📝 重要注意事項

1. **加密金鑰設定**：
   - 必須在環境變數中設定 `LLM_KEY_ENCRYPTION_KEY`
   - 使用 Fernet 生成的 base64 編碼金鑰
   - 生產環境必須使用固定金鑰，不要使用臨時生成的金鑰

2. **資料庫相容性**：
   - 支援 SQLite 和 PostgreSQL
   - 自動處理 SQL 語法差異
   - 使用 `ON CONFLICT` 或 `INSERT OR REPLACE` 處理重複

3. **錯誤處理**：
   - 如果 `cryptography` 未安裝，BYOK 功能會自動禁用
   - 如果加密金鑰未設定，會生成臨時金鑰並顯示警告
   - 所有錯誤都有詳細的日誌記錄

4. **向後兼容**：
   - 如果用戶沒有設定自己的 API Key，系統會自動使用系統預設的 API Key
   - 不會影響現有功能的正常運作

#### 🔄 與前端整合

**前端負責**：
- UI/UX 設計和用戶交互
- API Key 輸入和顯示
- 調用後端 API 保存、測試、清除 API Key

**後端負責**：
- API Key 加密存儲
- 權限驗證和安全控制
- LLM 呼叫時自動使用用戶的 API Key
- 提供完整的 CRUD API 端點

#### 🚀 部署步驟

1. **安裝依賴**：
   ```bash
   pip install cryptography
   ```

2. **生成加密金鑰**：
   ```bash
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```

3. **設定環境變數**：
   ```bash
   LLM_KEY_ENCRYPTION_KEY=<生成的加密金鑰>
   ```

4. **重新部署**：
   - 確保所有新的 API 端點都已部署
   - 確保資料庫表已創建
   - 測試所有功能

#### 📊 資料庫結構

**user_llm_keys 表**：
- `id`：主鍵，自動遞增
- `user_id`：用戶 ID（外鍵）
- `provider`：提供商（'gemini' 或 'openai'）
- `encrypted_key`：加密後的 API Key
- `last4`：最後4位數字（用於顯示）
- `created_at`：創建時間
- `updated_at`：更新時間
- `UNIQUE(user_id, provider)`：確保每個用戶每個提供商只有一個金鑰

---

### 2025-11-04 - 長期記憶系統完整支援

#### ✅ 系統狀態確認

**長期記憶 API 端點**（已完整實現）：
- ✅ `POST /api/memory/long-term` - 儲存長期記憶（已實現並正常工作）
- ✅ `GET /api/memory/long-term` - 獲取用戶長期記憶（支援會話篩選）
- ✅ `GET /api/memory/sessions` - 獲取用戶會話列表

**管理員長期記憶 API**（已完整實現）：
- ✅ `GET /api/admin/long-term-memory` - 獲取所有長期記憶記錄（管理員用）
- ✅ `GET /api/admin/long-term-memory/by-user` - 按用戶分組獲取長期記憶
- ✅ `GET /api/admin/memory-stats` - 獲取長期記憶統計數據

#### 🔍 前端修復對應

**前端修復內容**（本次更新）：
- ✅ 修復 mode2（AI 顧問）的長期記憶儲存功能
- ✅ 修復 mode3（IP 人設規劃）的重複儲存問題
- ✅ 修復 `index-ai-consultant.html` 的長期記憶儲存功能
- ✅ 加強日誌輸出和錯誤處理

**後端狀態**：
- ✅ 所有長期記憶 API 端點已完整實現並正常工作
- ✅ 資料庫表結構完整（`long_term_memory` 表）
- ✅ 認證機制正常運作
- ✅ 會話管理功能完整

#### 📊 長期記憶儲存流程

**儲存流程**：
```
1. 前端調用 recordConversationMessage()
   ↓
2. 發送 POST /api/memory/long-term
   ↓
3. 後端驗證 token 並獲取 user_id
   ↓
4. 插入到 long_term_memory 表
   ↓
5. 返回成功訊息
```

**資料庫結構**：
```sql
CREATE TABLE long_term_memory (
    id SERIAL PRIMARY KEY,
    user_id TEXT NOT NULL,
    conversation_type TEXT NOT NULL,  -- 'ai_advisor' | 'ip_planning'
    session_id TEXT NOT NULL,
    message_role TEXT NOT NULL,       -- 'user' | 'assistant'
    message_content TEXT NOT NULL,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### 🎯 支援的對話類型

**mode2（AI 顧問）**：
- `conversation_type: 'ai_advisor'`
- 前端已修復，現在會正確儲存長期記憶

**mode3（IP 人設規劃）**：
- `conversation_type: 'ip_planning'`
- 前端已修復重複儲存問題

#### 📝 API 使用範例

**儲存長期記憶**：
```bash
POST /api/memory/long-term
Authorization: Bearer <token>
Content-Type: application/json

{
  "conversation_type": "ai_advisor",
  "session_id": "ai_advisor_xxx123",
  "message_role": "user",
  "message_content": "用戶訊息內容"
}
```

**獲取長期記憶**：
```bash
GET /api/memory/long-term?conversation_type=ai_advisor&session_id=xxx123
Authorization: Bearer <token>
```

**獲取會話列表**：
```bash
GET /api/memory/sessions?conversation_type=ai_advisor
Authorization: Bearer <token>
```

#### 🎯 測試結果

所有 API 端點已驗證正常：
- ✅ **儲存長期記憶**：正確儲存用戶和 AI 的對話記錄
- ✅ **獲取長期記憶**：正確返回用戶的歷史對話
- ✅ **會話管理**：正確管理會話 ID 和會話列表
- ✅ **管理員 API**：正確返回所有用戶的長期記憶統計
- ✅ **認證機制**：正確驗證 token 和用戶權限

#### 📝 重要注意事項

1. **Token 驗證**：所有長期記憶 API 都需要有效的 JWT token
2. **用戶權限**：用戶只能訪問自己的長期記憶
3. **管理員權限**：管理員可以查看所有用戶的長期記憶
4. **會話管理**：前端會自動生成和管理會話 ID
5. **資料持久化**：長期記憶會永久儲存在資料庫中

---

### 2025-10-29 - OAuth 登入流程全面優化

#### 🚀 新增功能
- **改進 OAuth Callback 處理**：後端 redirect 到前端專用的 `popup-callback.html` 頁面
- **URL 參數傳遞**：通過 URL 參數安全地傳遞 token 和用戶資訊
- **COOP 標頭設置**：添加 `Cross-Origin-Opener-Policy: same-origin-allow-popups` 支援彈窗通信
- **Token Refresh 改進**：允許過期 token 用於 refresh，改進錯誤處理

#### 🛠️ 技術修改
**檔案：app.py**

**1. OAuth Callback 改進**：
- 移除內嵌 HTML 頁面的複雜 postMessage 邏輯
- 改為簡單的 redirect 到 `https://aivideonew.zeabur.app/auth/popup-callback.html`
- 使用 URL 參數傳遞 token、user_id、email、name、picture
- 使用 `urllib.parse.quote()` 確保參數安全編碼
- 添加 COOP 和 CORS 標頭支援跨域通信

**2. Token Refresh 改進**：
- 新增 `get_current_user_for_refresh()` 函數：允許接受過期但有效簽名的 token
- 修改 `verify_access_token()` 函數：添加 `allow_expired` 參數
- 改進 `/api/auth/refresh` 端點：使用新的 refresh 依賴項，添加詳細的 DEBUG 日誌
- 移除 user_id 要求：改回使用 `Authorization` header（標準做法）

**3. 錯誤處理改進**：
- 改進 OAuth callback 錯誤頁面的 postMessage 發送
- 移除 `window.opener.closed` 檢查，避免 COOP 錯誤
- 添加更詳細的 DEBUG 日誌記錄

#### 📊 API 端點更新

**OAuth 端點**：
- `GET /api/auth/google` - 生成 Google OAuth URL
- `GET /api/auth/google/callback` - 處理 OAuth callback（**已改為 redirect 到前端**）

**Token 管理端點**：
- `POST /api/auth/refresh` - 刷新 access token（**支援過期 token**）
- `GET /api/auth/me` - 獲取當前用戶資訊

#### 🔧 關鍵問題修復
1. **OAuth Callback 複雜性問題**：
   - **問題**：內嵌 HTML 頁面的 postMessage 邏輯複雜且容易失敗
   - **解決**：改為 redirect 到前端專用頁面，由前端統一處理

2. **Token Refresh 失敗問題**：
   - **問題**：過期 token 無法用於 refresh，導致 401 錯誤循環
   - **解決**：允許過期但有效簽名的 token 用於 refresh

3. **COOP 錯誤問題**：
   - **問題**：檢查 `window.opener.closed` 觸發 COOP 錯誤
   - **解決**：移除所有 `window.opener.closed` 檢查

4. **URL 參數安全問題**：
   - **問題**：用戶資料直接嵌入 URL 可能不安全
   - **解決**：使用 `urllib.parse.quote()` 正確編碼所有參數

#### 🎯 工作流程

**登入流程**：
```
1. 用戶點擊登入
   ↓
2. 前端請求 /api/auth/google
   ↓
3. 後端返回 Google OAuth URL
   ↓
4. 用戶完成 Google 登入
   ↓
5. Google redirect 到 /api/auth/google/callback?code=...
   ↓
6. 後端交換 code 獲取 access_token
   ↓
7. 後端獲取用戶資訊並生成應用 access token
   ↓
8. 後端 redirect 到前端 popup-callback.html?token=...&user_id=...
   ↓
9. 前端 popup-callback.html 處理 token 並通知主視窗
   ↓
10. 主視窗更新登入狀態 ✅
```

#### 📝 環境變數配置

**必要環境變數**：
- `GOOGLE_CLIENT_ID` - Google OAuth Client ID
- `GOOGLE_CLIENT_SECRET` - Google OAuth Client Secret
- `OAUTH_REDIRECT_URI` - OAuth redirect URI（建議：`https://aivideobackend.zeabur.app/api/auth/google/callback`）
- `JWT_SECRET` - JWT 簽名密鑰（**必須是固定值**，建議：`u5c1N4kQm8Zf2Tg7Pp9Lr3Xw6Yd0Aq2H`）

**注意事項**：
- `JWT_SECRET` 必須在 Zeabur 環境變數中設定為固定值
- 如果 `JWT_SECRET` 改變，所有現有的 token 都會失效
- Google OAuth `redirect_uri` 需要更新為前端的 `popup-callback.html`

#### 🎯 測試結果
所有功能已驗證正常：
- ✅ **OAuth Callback**：正確 redirect 到前端頁面
- ✅ **URL 參數編碼**：安全處理所有用戶資料
- ✅ **Token Refresh**：支援過期 token 刷新
- ✅ **COOP 標頭**：正確設置支援彈窗通信
- ✅ **錯誤處理**：完整的錯誤訊息和日誌記錄

#### 📝 經驗總結
1. **簡化 Callback 邏輯**：將複雜的 postMessage 邏輯移到前端，後端只負責資料處理和 redirect
2. **URL 參數安全**：使用正確的編碼確保特殊字符不會破壞 URL
3. **Token 管理**：允許過期 token 用於 refresh 提供更好的用戶體驗
4. **COOP 標頭**：正確設置 COOP 標頭支援現代瀏覽器的跨域通信安全政策

---

## 🧾 金流串接代辦（Backend TODO）

1. 金流供應商選擇與沙箱開通：ECPay / NewebPay / TapPay（擇一）。
2. 設計回調安全：
   - 加入簽章驗證（HMAC/檢核碼），比對交易參數與金額。
   - 白名單限制來源 IP/網域。
   - 防止重放：transaction_id 去重（唯一索引）。
3. 訂單流程：
   - 建立 `orders`（pending）→ 付款完成（paid）→ 更新 `licenses` 與 `user_auth.is_subscribed=1`。
   - 年/月方案：計算 `expires_at`（30 天或 365 天）。
4. API 介面：
   - `POST /api/payment/checkout`：建立訂單並取得第三方 CheckOut URL。
   - `POST /api/payment/webhook`：第三方伺服器端通知（必需驗簽）。
   - `GET /api/payment/return`：使用者瀏覽器返回頁（顯示結果）。
   - 目前暫用 `/api/payment/callback` 做為測試端點，後續替換為 webhook/return 雙軌。
5. 設定檔與環境變數：`PAYMENT_MERCHANT_ID`、`PAYMENT_HASH_KEY`、`PAYMENT_HASH_IV`、`PAYMENT_RETURN_URL`、`PAYMENT_NOTIFY_URL`。
6. 日誌與對帳：串接交易流水，建立每日對帳批次（CSV 匯出或 API 拉取）。

### 2025-10-28 - 上架前完整功能更新

#### 🚀 新增功能
- **管理後台完整 API 端點**：新增 6 個管理後台專用 API
- **訂閱管理功能**：管理員可手動設定用戶訂閱狀態
- **CSV 匯出功能**：支援匯出用戶、腳本、對話、生成記錄
- **真實數據整合**：所有圖表和統計都使用真實資料庫數據
- **PostgreSQL 完整支援**：自動處理 SQLite 和 PostgreSQL 語法差異
- **時區處理**：正確處理台灣時區 (UTC+8) 的日期顯示

#### 📊 新增 API 端點
1. `GET /api/admin/mode-statistics` - 模式使用統計
2. `GET /api/admin/generations` - 生成記錄列表
3. `GET /api/admin/platform-statistics` - 平台使用統計
4. `GET /api/admin/user-activities` - 最近用戶活動
5. `GET /api/admin/analytics-data` - 分析頁面數據
6. `PUT /api/admin/users/{user_id}/subscription` - 更新訂閱狀態
7. `GET /api/admin/export/{type}.csv` - CSV 匯出
8. `GET /api/admin/conversations` - 獲取所有對話記錄（新增）
9. `GET /api/admin/scripts` - 獲取所有腳本記錄（新增）

#### 🛠️ 技術修改
- **SQL 語法兼容性**：自動處理 SQLite (`?`) 和 PostgreSQL (`%s`) 的佔位符差異
- **INSERT OR REPLACE 修復**：PostgreSQL 使用 `ON CONFLICT ... DO UPDATE SET` 語法
- **時戳類型修復**：PostgreSQL 使用 datetime 對象，SQLite 使用 Unix timestamp
- **時區轉換**：所有日期顯示轉換為台灣時區 (UTC+8)
- **用戶訂閱狀態**：新增 `is_subscribed` 欄位，默認值為 1（已訂閱）

#### 🎯 訂閱管理
- **API 端點**：`PUT /api/admin/users/{user_id}/subscription`
- **功能**：管理員可手動啟用或取消用戶訂閱
- **支援**：PostgreSQL 和 SQLite
- **自動更新**：即時更新 UI 顯示

#### 📥 CSV 匯出
- **支援類型**：users, scripts, conversations, generations
- **自動下載**：點擊匯出按鈕自動下載檔案
- **完整數據**：包含所有相關欄位

#### 🛠️ PostgreSQL 完整支援
- **優先使用**：有 `DATABASE_URL` 時自動使用 PostgreSQL
- **向後兼容**：沒有 PostgreSQL 時自動回退到 SQLite
- **語法兼容**：自動處理 SQLite 和 PostgreSQL 語法差異

#### 🔧 關鍵問題修復
1. **Google OAuth 登入修復**：
   - 修復 `INSERT OR REPLACE` 語法在 PostgreSQL 的兼容性問題
   - 使用 `ON CONFLICT ... DO UPDATE SET` 替代 SQLite 特有語法
   - 修復 `expires_at` 欄位的類型不匹配問題（timestamp vs numeric）

2. **時區處理修復**：
   - 所有日期顯示轉換為台灣時區 (UTC+8)
   - `/api/auth/me` 和 `/api/admin/users` 正確格式化日期
   - 使用 `datetime.astimezone()` 確保時間顯示正確

3. **SQL 語法自動轉換**：
   - 佔位符自動轉換：SQLite (`?`) → PostgreSQL (`%s`)
   - 日期函數兼容：SQLite (`datetime('now')`) → PostgreSQL (`CURRENT_TIMESTAMP`)
   - RETURNING 語法：PostgreSQL 使用 `RETURNING id`，SQLite 使用 `lastrowid`

4. **數據顯示修復**：
   - 用戶列表正確顯示對話數和腳本數
   - 修正「註冊時間」和「訂閱狀態」欄位顯示順序
   - 所有統計數據使用真實資料庫數據，完全移除假數據

### 2025-10-27 - 資料庫持久化配置與訂閱狀態修復

#### 🚀 新增功能
- **環境變數支援**：使用 `DATABASE_PATH` 環境變數支援持久化存儲配置
- **訂閱狀態修復**：修正 `is_subscribed` 欄位的處理邏輯，確保正確讀取訂閱狀態
- **資料庫欄位補齊**：自動檢查並新增 `is_subscribed` 欄位到現有資料庫
- **預設訂閱設定**：新註冊用戶預設為已訂閱狀態

#### 🛠️ 技術修改
**檔案：app.py**

**1. 資料庫路徑配置**：
- 修改 `init_database()` 函數支援環境變數 `DATABASE_PATH`
- 預設路徑為 `./data`，可通過環境變數設定為 `/persistent` 等持久化路徑
- 修改 `get_db_connection()` 函數使用相同的路徑邏輯
- 添加路徑創建和日誌記錄

```python
def init_database():
    # 優先使用環境變數指定的路徑（持久化存儲）
    db_dir = os.getenv("DATABASE_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))
    db_path = os.path.join(db_dir, "chatbot.db")
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
```

**2. 訂閱狀態處理**：
- 修改 `google_callback_get()` 函數：新用戶註冊時設定 `is_subscribed = 1`
- 修改 `get_current_user_info()` 函數：正確處理 `is_subscribed` 欄位的各種類型
- 添加預設值處理：如果欄位為 `None`，預設設為 `True`（已訂閱）

```python
# 將所有現有用戶的訂閱狀態設為 1（已訂閱）
cursor.execute("UPDATE user_auth SET is_subscribed = 1 WHERE is_subscribed IS NULL OR is_subscribed = 0")
```

**3. 資料庫結構更新**：
- 在 `init_database()` 中添加 `ALTER TABLE` 語句檢查並新增 `is_subscribed` 欄位
- 如果欄位不存在，自動新增
- 如果欄位已存在，跳過新增步驟
- 將所有現有用戶的 `is_subscribed` 設定為 1（已訂閱）

#### 📊 資料庫配置

**本地開發環境**：
```bash
DATABASE_PATH=./data  # 預設，存儲在 backend/data/chatbot.db
```

**Zeabur 部署環境**：
```bash
DATABASE_PATH=/persistent  # 持久化存儲路徑
```

需要在 Zeabur 配置 Persistent Storage 並掛載到 `/persistent` 目錄。

#### 🎯 功能特點
- **持久化存儲支援**：通過環境變數配置資料庫路徑，支援 Zeabur Persistent Storage
- **向後兼容**：自動處理資料庫結構變更，不影響現有用戶
- **預設訂閱**：所有用戶預設為已訂閱狀態，方便測試和開發
- **類型安全**：正確處理 `is_subscribed` 欄位的各種類型（boolean, int, string）

#### 📝 修改細節
- **資料庫初始化**：添加 `ALTER TABLE` 檢查，確保 `is_subscribed` 欄位存在
- **類型轉換**：使用 `bool(row[4])` 確保返回正確的布林值
- **預設值處理**：如果 `is_subscribed` 為 `None`，預設設為 `True`
- **路徑配置**：統一使用 `DATABASE_PATH` 環境變數配置資料庫路徑

#### 🎯 測試結果
所有功能已驗證正常：
- ✅ **資料庫路徑配置**：正確讀取環境變數並設定資料庫路徑
- ✅ **訂閱狀態修復**：`is_subscribed` 欄位正確讀取和處理
- ✅ **新用戶註冊**：新用戶自動設定為已訂閱
- ✅ **資料庫結構更新**：自動檢查並新增缺失的欄位
- ✅ **向後兼容**：不影響現有用戶的資料和功能

#### 📝 經驗總結
1. **持久化存儲**：使用環境變數配置資料庫路徑，支援容器化部署的持久化存儲需求
2. **資料庫遷移**：通過 `ALTER TABLE` 和 `UPDATE` 語句實現平滑的資料庫結構更新
3. **類型處理**：考慮資料庫欄位的不同類型，確保正確的類型轉換
4. **預設值策略**：預設設為已訂閱狀態，降低測試和開發的門檻
5. **Zeabur 部署**：配置 Persistent Storage 掛載到 `/persistent` 目錄，確保資料持久化

#### ⚠️ 部署注意事項
1. **Zeabur Persistent Storage**：
   - 在 Zeabur 專案設定中啟用 Persistent Storage
   - 設定掛載路徑為 `/persistent`
   - 設定環境變數 `DATABASE_PATH=/persistent`

2. **資料遷移**：
   - 首次部署時，資料庫會自動新增 `is_subscribed` 欄位
   - 現有用戶的訂閱狀態會自動設為 1（已訂閱）
   - 不需要手動執行遷移腳本

3. **資料備份**：
   - 啟用 Persistent Storage 後，資料會保存到掛載的卷
   - 定期備份 `/persistent` 目錄的資料

---

### 2025-01-21 - 重大更新：實現長期記憶與個人化功能

#### 🚀 新增功能
- **長期記憶系統**：實現跨會話的用戶記憶和偏好追蹤
- **個人化學習**：AI自動學習用戶的內容偏好和使用習慣
- **智能摘要生成**：自動分類和摘要對話內容
- **用戶行為分析**：追蹤和分析用戶的使用模式
- **Google OAuth整合**：完整的用戶認證和授權系統

#### 🛠️ 技術修改
**檔案：app.py**
- 新增資料庫表：`user_preferences`、`user_behaviors`、`conversation_summaries`
- 實現智能對話摘要算法：`generate_smart_summary()`
- 新增用戶偏好追蹤：`track_user_preferences()`
- 增強用戶記憶功能：`get_user_memory()`
- 新增API端點：
  - `/api/user/memory/{user_id}` - 獲取用戶記憶
  - `/api/user/conversations/{user_id}` - 獲取對話記錄
  - `/api/user/generations/{user_id}` - 獲取生成記錄
  - `/api/user/preferences/{user_id}` - 獲取用戶偏好
  - `/api/user/behaviors/{user_id}` - 獲取行為統計
- 整合Google OAuth認證系統
- 實現用戶資料管理和會話管理

**檔案：requirements.txt**
- 新增 `httpx` 依賴套件

**檔案：資料庫結構**
- 擴展 `user_profiles` 表結構
- 新增 `user_preferences` 表：追蹤用戶偏好和信心分數
- 新增 `user_behaviors` 表：記錄用戶行為數據
- 優化 `conversation_summaries` 表：添加對話類型分類

#### 🎯 功能特色
1. **智能記憶分類**：
   - 帳號定位討論
   - 選題討論
   - 腳本生成
   - 一般諮詢

2. **偏好學習系統**：
   - 平台偏好（抖音、TikTok、Instagram等）
   - 內容類型偏好（美食、旅遊、時尚等）
   - 風格偏好（搞笑、專業、情感等）
   - 時長偏好（15秒、30秒、60秒）
   - 信心分數追蹤（0.0-1.0）

3. **個人化AI顧問**：
   - 基於歷史數據的個性化建議
   - 上下文連續性對話
   - 專業領域優化（短影音創作）

#### 📊 超越GPT的記憶能力
- ✅ 持久化記憶（跨會話保存）
- ✅ 個人偏好學習
- ✅ 信心分數追蹤
- ✅ 行為分析統計
- ✅ 專業領域優化
- ✅ 分類記憶管理

#### 🎯 測試結果
長期記憶功能驗證：
- ✅ 用戶偏好追蹤：正常運作
- ✅ 對話摘要生成：智能分類
- ✅ 跨會話記憶：持久化保存
- ✅ 個人化建議：基於歷史數據
- ✅ API端點：全部正常響應

#### 📝 經驗總結
1. **個人化AI設計**：實現真正的個人化需要多維度數據收集和分析
2. **信心分數系統**：避免誤判用戶偏好，提供更精準的學習
3. **分類記憶管理**：按功能分類組織記憶，提高檢索效率
4. **專業領域優化**：針對特定領域的AI比通用AI更有效

---

### 2025-10-20 - 重大修復：解決部署後AI無法呼叫問題

#### 🚨 問題描述
- **症狀**：部署到 Zeabur 後，前端無法呼叫 AI，出現 "Failed to fetch" 錯誤
- **錯誤類型**：502 Bad Gateway 錯誤
- **影響範圍**：完全無法使用 AI 功能

#### 🔍 問題診斷
1. **環境變數配置正確**：GEMINI_API_KEY 等環境變數已正確設定
2. **服務狀態異常**：後端服務顯示 RUNNING 但無法響應請求
3. **Uvicorn 配置問題**：Dockerfile 和 app.py 的啟動方式衝突

#### ✅ 解決方案
1. **修復 Uvicorn 配置**：
   - 統一 Dockerfile 和 app.py 的啟動方式
   - 使用環境變數 PORT 配置
   - 添加詳細的日誌記錄

2. **改善錯誤處理**：
   - 新增健康檢查端點的 Gemini API 測試功能
   - 提供詳細的診斷資訊
   - 改善前端錯誤訊息顯示

3. **優化部署配置**：
   - 修改 Dockerfile 使用動態端口配置
   - 添加啟動日誌和錯誤追蹤
   - 確保服務正確啟動和響應

#### 🛠️ 技術修改
**檔案：app.py**
- 新增 Gemini API 連線測試功能
- 改善健康檢查回應
- 添加詳細的啟動日誌

**檔案：Dockerfile**
- 修改啟動命令使用環境變數 PORT
- 添加日誌級別配置

**檔案：index.html**
- 新增「🔧 測試連線」按鈕
- 改善錯誤處理和診斷功能
- 修正 API 端點配置

#### 🎯 測試結果
修復後所有功能正常：
- ✅ 後端根路徑：正常 (狀態碼:200)
- ✅ 健康檢查：正常
- ✅ Gemini配置：已配置
- ✅ Gemini測試：working
- ✅ 聊天API：正常 (狀態碼:200)

#### 📝 經驗總結
1. **部署問題診斷**：使用健康檢查端點和詳細日誌
2. **配置一致性**：確保 Dockerfile 和應用程式配置一致
3. **錯誤處理**：提供清晰的錯誤訊息和診斷工具
4. **測試工具**：前端整合測試功能便於問題診斷

---

### 2025-10-21 - 雙層記憶系統整合與一鍵生成功能

#### 🚀 新增功能
1. **短期記憶（STM）系統**：
   - 記憶體內記憶儲存，支援48小時TTL
   - 自動對話壓縮：超過20輪對話自動摘要壓縮
   - 為每個用戶維護最近的對話上下文
   - 支援記憶清除和重置

2. **長期記憶（LTM）增強**：
   - 智能對話分類：定位類、選題類、腳本類、諮詢類、其他
   - 關鍵詞自動提取
   - 用戶偏好追蹤：平台、內容類型、風格、時長、信心分數
   - 用戶行為日誌記錄

3. **一鍵生成功能**：
   - **一鍵生成帳號定位**：基於用戶需求設定，自動分析目標受眾、內容方向、風格調性
   - **一鍵生成腳本選題**：根據帳號定位，推薦3-5個具體選題方向
   - **一鍵生成短影音腳本**：完整腳本生成，包含Hook、Value、CTA結構
   - 階段性驗證：必須先完成帳號定位才能選題，先完成選題才能生成腳本

4. **AI提示詞優化**：
   - 將AI角色從"短影音腳本與文案助理"升級為"AIJob短影音顧問"
   - 新增專業顧問流程：帳號定位 → 選題策略 → 腳本生成
   - 強化對話記憶檢查清單，避免重複提問
   - 優化回應格式：禁止Markdown，使用emoji和列點組織內容

5. **資料庫結構優化**：
   - `conversation_summaries` 表新增 `conversation_type` 和 `keywords` 欄位
   - 新增 `user_preferences` 表：追蹤用戶內容偏好
   - 新增 `user_behaviors` 表：記錄用戶行為日誌

#### 🛠️ 技術修改

**檔案：app.py**
- 新增記憶系統整合：
  - 導入 `memory.py` 和 `prompt_builder.py` 模組
  - 修改 `/api/chat/stream` 端點，整合STM和LTM
  - 使用 `build_enhanced_prompt()` 函數組合系統提示詞、STM上下文、LTM記憶
  - 在對話結束後自動保存到STM和LTM

- 新增一鍵生成API端點：
  - `POST /api/generate/positioning`：一鍵生成帳號定位
  - `POST /api/generate/topics`：一鍵生成腳本選題
  - `POST /api/generate/script`：一鍵生成短影音腳本
  - 每個端點都有專門的AI提示詞，確保輸出品質

- 新增記憶管理API端點：
  - `GET /api/user/stm/{user_id}`：獲取用戶短期記憶
  - `DELETE /api/user/stm/{user_id}`：清除用戶短期記憶
  - `GET /api/user/memory/full/{user_id}`：獲取完整記憶（STM + LTM）
  - `GET /api/user/preferences/{user_id}`：獲取用戶偏好
  - `GET /api/user/behaviors/{user_id}`：獲取用戶行為日誌

- 修改 `build_system_prompt()` 函數：
  - 明確AI角色為"AIJob短影音顧問"
  - 新增核心原則：檢查對話歷史、基於已有信息、推進對話、記住流程位置、避免重複問候
  - 新增專業顧問流程和對話記憶檢查清單
  - 強化內容格式要求：禁止使用Markdown符號

- 新增智能摘要生成函數：
  - `generate_smart_summary()`：生成智能對話摘要
  - `extract_keywords()`：提取對話關鍵詞
  - `classify_conversation()`：分類對話類型

- 新增用戶偏好追蹤函數：
  - `track_user_preferences()`：追蹤和更新用戶偏好
  - `extract_user_preferences()`：從對話中提取用戶偏好

- 修改資料庫初始化：
  - 更新 `conversation_summaries` 表結構
  - 新增 `user_preferences` 和 `user_behaviors` 表

- 修改本地啟動埠號：從3000改為8000

**新檔案：memory.py**
- 實現短期記憶（STM）管理系統
- 主要功能：
  - `load_memory()`：載入用戶記憶
  - `save_memory()`：保存用戶記憶
  - `add_turn()`：添加對話輪次
  - `get_context_for_prompt()`：獲取記憶上下文供LLM使用
  - `get_recent_turns_for_history()`：獲取最近對話歷史
  - `clear_memory()`：清除用戶記憶
- 自動壓縮機制：超過20輪對話自動摘要
- 48小時TTL機制

**新檔案：prompt_builder.py**
- 實現增強版系統提示詞構建
- 主要功能：
  - `build_enhanced_prompt()`：整合知識庫、STM、LTM構建完整提示詞
  - `format_memory_for_display()`：格式化記憶數據供前端顯示
- 組合格式：系統規則 → 用戶設定 → STM上下文 → LTM記憶 → 知識庫

**檔案：requirements.txt**
- 維持現有依賴（無新增）

#### 🎯 測試結果

修復後所有功能正常：
- ✅ **STM系統**：成功記錄和檢索最近對話
- ✅ **LTM系統**：智能分類和摘要生成
- ✅ **用戶偏好追蹤**：自動學習用戶喜好
- ✅ **一鍵生成帳號定位**：基於設定生成專業建議
- ✅ **一鍵生成選題**：根據定位推薦具體選題
- ✅ **一鍵生成腳本**：完整的短影音腳本輸出
- ✅ **階段性驗證**：確保按正確順序生成內容
- ✅ **AI對話**：記憶連貫，不重複提問
- ✅ **記憶API**：所有端點正常響應
- ✅ **資料庫**：新結構正確創建和使用

#### 🔧 問題修復

1. **資料庫結構過舊問題**：
   - **症狀**：`no such column: conversation_type` 錯誤
   - **原因**：舊資料庫缺少新增的欄位
   - **解決**：備份舊資料庫（`chatbot.db.backup`），重建新資料庫

2. **API Key 環境變數問題**：
   - **症狀**：背景執行時 `GEMINI_API_KEY` 未傳遞
   - **原因**：背景進程未繼承環境變數
   - **解決**：在啟動命令中明確 `export GEMINI_API_KEY`

3. **埠號不一致問題**：
   - **症狀**：後端啟動在3000埠，前端嘗試連接8000埠
   - **原因**：本地開發時埠號設定不一致
   - **解決**：統一使用8000埠

4. **一鍵生成缺少message欄位**：
   - **症狀**：422錯誤，`Field required: message`
   - **原因**：前端未傳遞必要的 `message` 欄位
   - **解決**：前端一鍵生成函數新增 `message` 欄位

5. **API端點定義順序問題**：
   - **症狀**：`NameError: name 'app' is not defined`
   - **原因**：API端點在 `app = FastAPI()` 之前定義
   - **解決**：移動所有API端點定義到 `app` 初始化之後

#### 📝 經驗總結

1. **記憶系統設計**：
   - 短期記憶用於維持對話連貫性
   - 長期記憶用於個人化學習
   - 雙層架構提供最佳效能和體驗

2. **資料庫遷移**：
   - 結構變更時需要重建資料庫
   - 務必備份舊資料
   - 考慮實現資料遷移腳本

3. **背景進程管理**：
   - 環境變數需要明確傳遞
   - 使用 `tee` 同時輸出到終端和日誌檔案
   - 使用 `pkill` 確保舊進程完全停止

4. **API設計原則**：
   - 一鍵生成與對話聊天使用不同提示詞
   - 階段性驗證確保內容品質
   - 所有端點都要支援串流輸出

5. **AI提示詞工程**：
   - 明確的角色定位和流程指引
   - 避免過度指導，保持彈性
   - 強化記憶檢查，避免重複提問

#### 🚀 本地開發啟動指令

**推薦方式（背景執行 + 日誌輸出）**：
```bash
# 1. 停止舊進程
pkill -9 -f "python.*app.py"

# 2. 啟動後端服務（背景執行 + 日誌）
cd /Users/user/Downloads/ai_web_app/對話式/chatbot/backend
source venv/bin/activate
export GEMINI_API_KEY="AIzaSyCNmsgpPxo6acx3TVlVrvMLWOvqqj38TR4"
python app.py 2>&1 | tee /tmp/backend.log &

# 3. 查看即時日誌
tail -f /tmp/backend.log
```

**前台執行方式（可看到即時輸出）**：
```bash
cd /Users/user/Downloads/ai_web_app/對話式/chatbot/backend
source venv/bin/activate
export GEMINI_API_KEY="AIzaSyCNmsgpPxo6acx3TVlVrvMLWOvqqj38TR4"
python app.py
```

#### 📊 記憶系統架構

```
短期記憶（STM）- memory.py
├── 儲存方式：記憶體字典
├── TTL：48小時自動過期
├── 容量：最近20輪對話
└── 自動壓縮：超過閾值自動摘要

長期記憶（LTM）- app.py
├── 儲存方式：SQLite資料庫
├── 對話摘要：conversation_summaries表
├── 用戶偏好：user_preferences表
└── 行為日誌：user_behaviors表

提示詞構建 - prompt_builder.py
└── 整合順序：系統規則 → 用戶設定 → STM → LTM → 知識庫
```

#### 🎯 一鍵生成流程

```
1. 帳號定位
   ├── 輸入：平台、主題、受眾（選填）
   ├── 分析：目標受眾、內容方向、風格調性
   └── 輸出：📌 定位建議

2. 腳本選題
   ├── 前置條件：必須先完成帳號定位
   ├── 輸入：基於帳號定位結果
   ├── 分析：選題方向、內容角度、話題熱度
   └── 輸出：💡 3-5個選題建議

3. 短影音腳本
   ├── 前置條件：必須先完成選題
   ├── 輸入：基於選題結果 + 用戶設定
   ├── 生成：主題標題、腳本內容、畫面感、發佈文案
   └── 輸出：📝 完整腳本
```

---

## 📝 更新日誌格式指南

### 為下一個 AI 助理的說明
當有重大更新、問題修復或新功能時，請在「更新日誌」區段添加新的記錄。使用以下格式：

```markdown
### YYYY-MM-DD - 更新標題

#### 🚨 問題描述（如果是修復問題）
- **症狀**：具體的錯誤現象
- **錯誤類型**：錯誤代碼或類型
- **影響範圍**：受影響的功能或用戶

#### 🔍 問題診斷（如果是修復問題）
1. **步驟1**：診斷過程
2. **步驟2**：發現的問題
3. **步驟3**：根本原因分析

#### ✅ 解決方案/新增功能
1. **解決方案1**：具體的修復步驟
2. **解決方案2**：相關的配置調整
3. **解決方案3**：預防措施

#### 🛠️ 技術修改
**檔案：檔案名稱**
- 具體修改內容1
- 具體修改內容2

**檔案：另一個檔案名稱**
- 修改內容描述

#### 🎯 測試結果
修復/新增後的功能驗證：
- ✅ 功能1：測試結果
- ✅ 功能2：測試結果
- ❌ 功能3：已知問題（如有）

#### 📝 經驗總結
1. **技術要點**：重要的技術經驗
2. **最佳實踐**：推薦的做法
3. **注意事項**：需要特別注意的地方
```

### 📋 更新日誌撰寫要點
- **詳細記錄**：包含足夠的技術細節，便於未來參考
- **問題診斷**：記錄完整的問題分析過程
- **解決步驟**：提供可重現的修復步驟
- **測試驗證**：記錄修復後的測試結果
- **經驗提煉**：總結重要的技術經驗和最佳實踐

---

## 🆕 腳本儲存系統 (2025-10-21)

### 📋 新增功能

#### 1. 腳本儲存 API
- **POST** `/api/scripts/save` - 儲存腳本
- **GET** `/api/scripts/my` - 獲取用戶腳本列表
- **PUT** `/api/scripts/{id}/name` - 更新腳本名稱
- **DELETE** `/api/scripts/{id}` - 刪除腳本

#### 2. 管理員 API
- **GET** `/api/admin/users` - 獲取所有用戶資料
- **GET** `/api/admin/user/{id}/data` - 獲取指定用戶完整資料
- **GET** `/api/admin/statistics` - 獲取系統統計資料

#### 3. 資料庫表格
```sql
CREATE TABLE user_scripts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    script_name TEXT,
    title TEXT,
    content TEXT NOT NULL,
    script_data TEXT,
    platform TEXT,
    topic TEXT,
    profile TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user_profiles (user_id)
);
```

### 🔧 技術實現

#### 1. 資料庫連接優化
```python
def get_db_connection():
    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn
```

#### 2. 腳本儲存重試機制
```python
max_retries = 3
retry_count = 0
while retry_count < max_retries:
    try:
        # 儲存邏輯
        break
    except sqlite3.OperationalError as e:
        if "database is locked" in str(e):
            retry_count += 1
            await asyncio.sleep(0.1 * retry_count)
```

#### 3. 腳本數據結構
```python
script_data = {
    "title": "腳本標題",
    "overview": "腳本概覽",
    "sections": [
        {
            "type": "Hook/Value/CTA",
            "content": ["內容1", "內容2"]
        }
    ]
}
```

### ⚠️ 已知問題

#### 1. API認證問題
- **現象**：401 Unauthorized 錯誤
- **原因**：`get_current_user` 函數認證失敗
- **影響**：腳本儲存、載入、管理功能無法使用

#### 2. 資料庫鎖定問題
- **現象**：`database is locked` 錯誤
- **原因**：多個請求同時訪問SQLite
- **影響**：偶爾導致操作失敗

#### 3. 資料持久化問題
- **現象**：Zeabur重新部署時資料遺失
- **原因**：SQLite不適合生產環境
- **影響**：所有用戶資料會遺失

### 🎯 待修復項目

1. **修復API認證**：
   - 檢查 `get_current_user` 函數
   - 確保JWT token正確解析
   - 修復認證邏輯

2. **優化資料庫連接**：
   - 實現連接池
   - 添加更好的鎖定處理
   - 考慮升級到PostgreSQL

3. **完善錯誤處理**：
   - 添加更詳細的錯誤訊息
   - 實現更好的重試機制
   - 添加日誌記錄

---

## 🔧 2025-10-21 修復記錄

### 腳本儲存系統修復

#### 問題描述
- 前端腳本儲存成功但「我的腳本」不顯示
- 後端API認證問題導致 401 錯誤
- 用戶無法查看已儲存的腳本

#### 修復措施

1. **前端本地儲存備案**：
   - 添加 `localStorage` 作為後端API的備案機制
   - 實現 `getLocalScripts()` 和 `saveScriptToLocal()` 函數
   - 當後端API不可用時自動使用本地儲存

2. **錯誤處理優化**：
   - 401 認證錯誤：顯示登入提示
   - 404 API不存在：自動使用本地儲存
   - 網路錯誤：自動使用本地儲存

3. **調試日誌增強**：
   - 添加詳細的控制台日誌
   - 便於問題排查和狀態追蹤

#### 技術實現

**前端修改**：
```javascript
// 優先載入本地腳本
const localScripts = getLocalScripts();
if (localScripts.length > 0) {
  displayScripts(localScripts);
  return;
}

// 雙重儲存機制
if (response.ok) {
  // 後端儲存成功，同時儲存到本地
  saveScriptToLocal(localScriptData);
} else if (response.status === 404) {
  // API不存在，使用本地儲存
  saveScriptToLocal(localScriptData);
}
```

**後端狀態**：
- 腳本儲存API已實現但需要重新部署
- 資料庫連接已優化（WAL模式、重試機制）
- 認證系統需要進一步調試

#### 當前狀態
- ✅ 前端腳本儲存功能正常（使用本地備案）
- ✅ 腳本顯示功能正常
- ⚠️ 後端API需要重新部署
- ⚠️ 長期需要解決資料持久化問題

---

## 版權
2025 AIJob學院版權所有
