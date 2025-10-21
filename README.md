# AI 短影音智能體 - 後端服務

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
GEMINI_API_KEY=your_gemini_api_key
GEMINI_MODEL=gemini-2.5-flash
KB_PATH=/app/data/kb.txt
```

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
export GEMINI_API_KEY="your_gemini_api_key"

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

## 版權
2025 AIJob學院版權所有
