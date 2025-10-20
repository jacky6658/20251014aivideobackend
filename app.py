import os
import json
from datetime import datetime
from typing import List, Dict, Any, Optional, Iterable

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv

import google.generativeai as genai


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatBody(BaseModel):
    message: str
    platform: Optional[str] = None
    profile: Optional[str] = None
    history: Optional[List[ChatMessage]] = None
    topic: Optional[str] = None
    style: Optional[str] = None
    duration: Optional[str] = "30"


def resolve_kb_path() -> Optional[str]:
    env_path = os.getenv("KB_PATH")
    if env_path and os.path.isfile(env_path):
        return env_path

    # Try common relative locations
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.abspath(os.path.join(here, "data", "kb.txt")),  # 當前目錄下的 data/kb.txt
        os.path.abspath(os.path.join(here, "..", "AI短影音智能體重製版", "data", "kb.txt")),
        os.path.abspath(os.path.join(here, "..", "data", "kb.txt")),
        os.path.abspath(os.path.join(here, "..", "..", "AI短影音智能體重製版", "data", "kb.txt")),
        os.path.abspath(os.path.join(here, "..", "..", "data", "kb.txt")),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def load_kb_text() -> str:
    kb_path = resolve_kb_path()
    if not kb_path:
        return ""
    try:
        with open(kb_path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return ""


def build_system_prompt(kb_text: str, platform: Optional[str], profile: Optional[str], topic: Optional[str], style: Optional[str], duration: Optional[str]) -> str:
    platform_line = f"平台：{platform}" if platform else "平台：未指定"
    profile_line = f"帳號定位：{profile}" if profile else "帳號定位：未指定"
    topic_line = f"主題：{topic}" if topic else "主題：未指定"
    duration_line = f"腳本時長：{duration}秒" if duration else "腳本時長：30秒"
    kb_header = "短影音知識庫（節錄）：\n" if kb_text else ""
    rules = (
        "請你扮演短影音腳本與文案助理，所有回答盡量口語化、短句、節奏快，避免口頭禪。\n"
        "優先依據提供的知識庫回答；若超出範圍可補充一般經驗並標示『[一般經驗]』。\n"
        "\n"
        "回答流程：\n"
        "1. 先理解並回答用戶的問題或需求\n"
        "2. 提供相關建議和思路\n"
        "3. 當用戶明確要求「生成腳本」、「製作腳本」、「寫腳本」時，才提供完整腳本\n"
        "4. 完整腳本必須包含明確的「Hook」、「Value」、「CTA」標記\n"
        "\n"
        "內容格式要求：\n"
        "• 使用數字標示（1. 2. 3.）或列點（•）來組織內容\n"
        "• 用 emoji 來分段和強調重點（如：🚀 💡 ✅ 📌）\n"
        "• 絕對禁止使用 * 或 ** 等任何 Markdown 格式符號\n"
        "• 不要使用粗體、斜體等格式標記\n"
        "• 每段之間用換行分隔，保持清晰易讀\n"
        "• 所有內容都必須是純文字格式，沒有任何程式碼符號\n"
        "\n"
        "腳本結構：盡量對齊 Hook → Value → CTA 結構；Value 不超過三點，CTA 給一個明確動作。\n"
        "完整腳本應包含：\n"
        "1. 主題標題\n"
        "2. 腳本內容（只包含台詞、秒數、CTA，不包含畫面描述）\n"
        "3. 畫面感（鏡頭、音效建議）\n"
        "4. 發佈文案\n"
    )
    style_line = style or "格式要求：分段清楚，短句，每段換行，適度加入表情符號（如：✅✨🔥📌），避免口頭禪。使用數字標示（1. 2. 3.）或列點（•）來組織內容，不要使用 * 或 ** 等 Markdown 格式。"
    return f"{platform_line}\n{profile_line}\n{topic_line}\n{duration_line}\n{style_line}\n\n{rules}\n{kb_header}{kb_text}"


def create_app() -> FastAPI:
    load_dotenv()

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("WARNING: GEMINI_API_KEY not found in environment variables")
        # Delay failure to request time but keep app creatable
    else:
        print(f"INFO: GEMINI_API_KEY found, length: {len(api_key)}")

    genai.configure(api_key=api_key)
    model_name = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    print(f"INFO: Using model: {model_name}")

    app = FastAPI()

    # CORS for local file or dev servers
    frontend_url = os.getenv("FRONTEND_URL")
    cors_origins = [
        "*",  # 允許所有來源（開發用）
        "http://localhost:8080",  # 本地開發前端
        "http://127.0.0.1:8080"   # 本地開發前端
    ]
    
    # 如果有設定前端 URL，加入 CORS 來源
    if frontend_url:
        cors_origins.append(frontend_url)
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    kb_text_cache = load_kb_text()

    @app.get("/")
    async def root():
        return {"message": "AI Video Backend is running"}
    
    @app.get("/api/health")
    async def health() -> Dict[str, Any]:
        try:
            kb_status = "loaded" if kb_text_cache else "not_found"
            gemini_configured = bool(os.getenv("GEMINI_API_KEY"))
            
            # 測試 Gemini API 連線（如果已配置）
            gemini_test_result = "not_configured"
            if gemini_configured:
                try:
                    model = genai.GenerativeModel(model_name)
                    # 簡單測試呼叫
                    response = model.generate_content("test", request_options={"timeout": 5})
                    gemini_test_result = "working" if response else "failed"
                except Exception as e:
                    gemini_test_result = f"error: {str(e)}"
            
            return {
                "status": "ok",
                "kb_status": kb_status,
                "gemini_configured": gemini_configured,
                "gemini_test": gemini_test_result,
                "model_name": model_name,
                "timestamp": str(datetime.now())
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "timestamp": str(datetime.now())
            }

    @app.post("/api/chat/stream")
    async def stream_chat(body: ChatBody, request: Request):
        if not os.getenv("GEMINI_API_KEY"):
            return JSONResponse({"error": "Missing GEMINI_API_KEY in .env"}, status_code=500)

        # Prepare system + history
        system_text = build_system_prompt(kb_text_cache, body.platform, body.profile, body.topic, body.style, body.duration)

        user_history: List[Dict[str, Any]] = []
        for m in body.history or []:
            if m.role == "user":
                user_history.append({"role": "user", "parts": m.content})
            elif m.role in ("assistant", "model"):
                user_history.append({"role": "model", "parts": m.content})

        model = genai.GenerativeModel(model_name)
        chat = model.start_chat(history=[
            {"role": "user", "parts": system_text},
            *user_history,
        ])

        def sse_events() -> Iterable[str]:
            yield f"data: {json.dumps({'type': 'start'})}\n\n"
            try:
                stream = chat.send_message(body.message, stream=True)
                for chunk in stream:
                    try:
                        if chunk and getattr(chunk, "candidates", None):
                            parts = chunk.candidates[0].content.parts
                            if parts:
                                token = parts[0].text
                                if token:
                                    yield f"data: {json.dumps({'type': 'token', 'content': token})}\n\n"
                    except Exception:
                        continue
            except Exception as e:
                yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
            finally:
                yield f"data: {json.dumps({'type': 'end'})}\n\n"

        return StreamingResponse(sse_events(), media_type="text/event-stream")

    return app


app = create_app()

# 注意：在 Zeabur 部署時，使用 Dockerfile 中的 uvicorn 命令啟動
# 這個區塊主要用於本地開發
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 3000))
    print(f"INFO: Starting Uvicorn locally on host=0.0.0.0, port={port}")
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=port,
        log_level="info",
        access_log=True,
        workers=1
    )


