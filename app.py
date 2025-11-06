import os
import json
import hashlib
import sqlite3
import secrets
import asyncio
import time
import uuid
import base64
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Iterable, TYPE_CHECKING
from urllib.parse import urlparse, urlencode
import urllib.parse
import logging
import re
import ipaddress

# 設定日誌
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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

# BYOK 加密支援
if TYPE_CHECKING:
    from cryptography.fernet import Fernet

try:
    from cryptography.fernet import Fernet
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    Fernet = None  # 當未安裝時設為 None，避免類型提示錯誤
    print("WARNING: cryptography 未安裝，BYOK 功能將無法使用。請執行: pip install cryptography")

# 台灣時區 (GMT+8)
TAIWAN_TZ = timezone(timedelta(hours=8))

def get_taiwan_time():
    """獲取台灣時區的當前時間"""
    return datetime.now(TAIWAN_TZ)


# ===== BYOK 加密功能 =====

def get_encryption_key() -> Optional[bytes]:
    """獲取加密金鑰（從環境變數或生成）
    
    生產環境必須設定 LLM_KEY_ENCRYPTION_KEY 環境變數。
    金鑰必須是 32 字節的 base64 編碼字串（Fernet 格式）。
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        return None
    
    encryption_key_str = os.getenv("LLM_KEY_ENCRYPTION_KEY")
    if not encryption_key_str:
        # 生產環境必須設定，否則拋出錯誤
        raise ValueError("LLM_KEY_ENCRYPTION_KEY 環境變數未設定，生產環境必須設定")
    
    # 驗證金鑰格式（Fernet 金鑰必須是 32 字節的 base64 編碼）
    try:
        key_bytes = base64.urlsafe_b64decode(encryption_key_str)
        if len(key_bytes) != 32:
            raise ValueError("LLM_KEY_ENCRYPTION_KEY 格式錯誤，必須是 32 字節的 base64 編碼")
        return encryption_key_str.encode()
    except Exception as e:
        raise ValueError(f"LLM_KEY_ENCRYPTION_KEY 格式錯誤: {e}")


def get_cipher() -> Optional["Fernet"]:
    """獲取加密器"""
    if not CRYPTOGRAPHY_AVAILABLE or Fernet is None:
        return None
    
    try:
        key = get_encryption_key()
        if not key:
            return None
        
        try:
            return Fernet(key)
        except Exception as e:
            print(f"ERROR: 創建加密器失敗: {e}")
            return None
    except ValueError as e:
        # 環境變數未設定或格式錯誤，但不影響應用啟動
        print(f"WARNING: {e}")
        return None


def encrypt_api_key(api_key: str) -> Optional[str]:
    """加密 API Key"""
    cipher = get_cipher()
    if not cipher:
        raise ValueError("加密功能不可用，請安裝 cryptography 並設定 LLM_KEY_ENCRYPTION_KEY")
    
    try:
        encrypted = cipher.encrypt(api_key.encode())
        return encrypted.decode()
    except Exception as e:
        print(f"ERROR: 加密 API Key 失敗: {e}")
        raise


def decrypt_api_key(encrypted_key: str) -> Optional[str]:
    """解密 API Key"""
    cipher = get_cipher()
    if not cipher:
        print("WARNING: 加密功能不可用，無法解密 API Key")
        return None
    
    try:
        # 檢查輸入格式
        if not encrypted_key or not isinstance(encrypted_key, str):
            print(f"ERROR: 解密 API Key 失敗 - 輸入格式錯誤: {type(encrypted_key)}, 長度: {len(encrypted_key) if encrypted_key else 0}")
            return None
        
        # 檢查是否為有效的 base64 格式（Fernet 加密後的格式）
        try:
            import base64
            # 嘗試解碼 base64（不驗證內容，只檢查格式）
            base64.urlsafe_b64decode(encrypted_key + '==')  # 添加填充嘗試解碼
        except Exception as base64_error:
            print(f"ERROR: 解密 API Key 失敗 - 不是有效的 base64 格式: {str(base64_error)}")
            print(f"DEBUG: encrypted_key 前50個字符: {encrypted_key[:50] if len(encrypted_key) > 50 else encrypted_key}")
            return None
        
        # 嘗試解密
        decrypted = cipher.decrypt(encrypted_key.encode())
        return decrypted.decode()
    except Exception as e:
        error_msg = str(e) if e else "未知錯誤"
        error_type = type(e).__name__
        print(f"ERROR: 解密 API Key 失敗 - 類型: {error_type}, 訊息: {error_msg}")
        print(f"DEBUG: encrypted_key 長度: {len(encrypted_key) if encrypted_key else 0}")
        print(f"DEBUG: encrypted_key 前50個字符: {encrypted_key[:50] if encrypted_key and len(encrypted_key) > 50 else encrypted_key}")
        # 不拋出異常，返回 None（因為這是可選功能，不應該中斷主流程）
        # 可能是舊金鑰加密的數據，無法用新金鑰解密
        return None


def get_user_llm_key(user_id: Optional[str], provider: str = "gemini") -> Optional[str]:
    """獲取用戶的 LLM API Key（如果有的話）"""
    if not CRYPTOGRAPHY_AVAILABLE or not user_id:
        return None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        database_url = os.getenv("DATABASE_URL")
        use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
        
        if use_postgresql:
            cursor.execute(
                "SELECT encrypted_key FROM user_llm_keys WHERE user_id = %s AND provider = %s",
                (user_id, provider)
            )
        else:
            cursor.execute(
                "SELECT encrypted_key FROM user_llm_keys WHERE user_id = ? AND provider = ?",
                (user_id, provider)
            )
        
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if row:
            encrypted_key = row[0]
            if encrypted_key:
                decrypted_key = decrypt_api_key(encrypted_key)
                if decrypted_key:
                    return decrypted_key
                else:
                    # 解密失敗（可能是舊金鑰加密的數據）
                    print(f"WARNING: 無法解密用戶 {user_id} 的 {provider} API Key，可能是使用舊金鑰加密的數據")
                    return None
            else:
                return None
        
        return None
    except Exception as e:
        error_msg = str(e) if e else "未知錯誤"
        error_type = type(e).__name__
        print(f"ERROR: 獲取用戶 LLM Key 失敗 - 類型: {error_type}, 訊息: {error_msg}")
        return None

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse, RedirectResponse, HTMLResponse, Response, PlainTextResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from dotenv import load_dotenv
import httpx

import google.generativeai as genai

# PostgreSQL 支援
try:
    import psycopg2
    from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False
    print("WARNING: psycopg2 未安裝，將使用 SQLite")


# 導入新的記憶系統模組
from memory import stm
from prompt_builder import build_enhanced_prompt, format_memory_for_display


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
    user_id: Optional[str] = None  # 新增用戶ID


class UserProfile(BaseModel):
    user_id: str
    preferred_platform: Optional[str] = None
    preferred_style: Optional[str] = None
    preferred_duration: Optional[str] = "30"
    content_preferences: Optional[Dict[str, Any]] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class Generation(BaseModel):
    id: Optional[str] = None
    user_id: str
    content: str
    platform: Optional[str] = None
    topic: Optional[str] = None
    dedup_hash: Optional[str] = None  # 改為可選，後端自動生成
    created_at: Optional[datetime] = None


class ConversationSummary(BaseModel):
    user_id: str
    summary: str
    message_count: int
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class GoogleUser(BaseModel):
    id: str
    email: str
    name: str
    picture: Optional[str] = None
    verified_email: bool = False


class AuthToken(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: GoogleUser


class LongTermMemoryRequest(BaseModel):
    conversation_type: str
    session_id: str
    message_role: str
    message_content: str
    metadata: Optional[str] = None


# 載入環境變數
load_dotenv()

# OAuth 配置（從環境變數讀取）
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("OAUTH_REDIRECT_URI", "http://localhost:5173/auth/callback")
FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", "https://aivideonew.zeabur.app")
# 允許作為回跳前端的白名單（避免任意導向）
ALLOWED_FRONTENDS = {
    "https://aivideonew.zeabur.app",
    "https://reelmind.aijob.com.tw",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:8000",  # 本地測試（Python http.server）
    "http://127.0.0.1:8000",  # 本地測試（Python http.server）
    "http://localhost:8080",  # 其他常用本地端口
    "http://127.0.0.1:8080",  # 其他常用本地端口
}

# 除錯資訊
print(f"DEBUG: Environment variables loaded:")
print(f"DEBUG: GOOGLE_CLIENT_ID: {GOOGLE_CLIENT_ID}")
print(f"DEBUG: GOOGLE_CLIENT_SECRET: {GOOGLE_CLIENT_SECRET}")
print(f"DEBUG: GOOGLE_REDIRECT_URI: {GOOGLE_REDIRECT_URI}")
print(f"DEBUG: FRONTEND_BASE_URL: {FRONTEND_BASE_URL}")

# JWT 密鑰（用於生成訪問令牌）
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_urlsafe(32))

# ECPay 金流配置
ECPAY_MERCHANT_ID = os.getenv("ECPAY_MERCHANT_ID")
ECPAY_HASH_KEY = os.getenv("ECPAY_HASH_KEY")
ECPAY_HASH_IV = os.getenv("ECPAY_HASH_IV")
ECPAY_API = os.getenv("ECPAY_API", "https://payment-stage.ecpay.com.tw/Cashier/AioCheckOut/V5")  # 預設測試環境
ECPAY_RETURN_URL = os.getenv("ECPAY_RETURN_URL", "https://aivideonew.zeabur.app/subscription.html")
ECPAY_NOTIFY_URL = os.getenv("ECPAY_NOTIFY_URL", "https://aivideobackend.zeabur.app/api/payment/webhook")

# ECPay IP 白名單（從環境變數讀取，支援多個 IP 範圍，用逗號分隔）
ECPAY_IP_WHITELIST_STR = os.getenv("ECPAY_IP_WHITELIST", "210.200.4.0/24,210.200.5.0/24")
ECPAY_IP_WHITELIST = [ip.strip() for ip in ECPAY_IP_WHITELIST_STR.split(",") if ip.strip()]

# ECPay 發票設定
ECPAY_INVOICE_ENABLED = os.getenv("ECPAY_INVOICE_ENABLED", "false").lower() == "true"
ECPAY_INVOICE_MERCHANT_ID = os.getenv("ECPAY_INVOICE_MERCHANT_ID")  # 發票商店代號（可能與付款不同）
ECPAY_INVOICE_API = os.getenv("ECPAY_INVOICE_API", "https://einvoice-stage.ecpay.com.tw/Invoice/Issue")  # 測試環境
# ECPAY_INVOICE_API=https://einvoice.ecpay.com.tw/Invoice/Issue  # 生產環境

# 安全認證
security = HTTPBearer()


# SQL 語法轉換輔助函數
def convert_sql_for_postgresql(sql: str) -> str:
    """將 SQLite 語法轉換為 PostgreSQL 語法"""
    # 轉換 AUTOINCREMENT
    sql = sql.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
    sql = sql.replace("AUTOINCREMENT", "")
    
    # 轉換 TEXT 和 VARCHAR
    # 保留 TEXT 類型（PostgreSQL 也支援）
    # 但主鍵用 VARCHAR
    if "PRIMARY KEY" in sql:
        sql = sql.replace("TEXT PRIMARY KEY", "VARCHAR(255) PRIMARY KEY")
    
    # INTEGER -> INTEGER (PostgreSQL 也支援)
    # REAL -> REAL (PostgreSQL 也支援)
    
    return sql


# 數據庫初始化
def init_database():
    """初始化資料庫（支援 PostgreSQL 和 SQLite）"""
    database_url = os.getenv("DATABASE_URL")
    
    # 判斷使用哪種資料庫
    use_postgresql = False
    conn = None
    
    if database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE:
        use_postgresql = True
        print(f"INFO: 初始化 PostgreSQL 資料庫")
        conn = psycopg2.connect(database_url)
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()
    else:
        # 使用 SQLite
        db_dir = os.getenv("DATABASE_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))
        db_path = os.path.join(db_dir, "chatbot.db")
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        print(f"INFO: 初始化 SQLite 資料庫: {db_path}")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
    
    # 輔助函數：執行 SQL 並自動轉換語法
    def execute_sql(sql: str):
        if use_postgresql:
            sql = convert_sql_for_postgresql(sql)
        cursor.execute(sql)
    
    # 創建用戶偏好表
    execute_sql("""
        CREATE TABLE IF NOT EXISTS user_profiles (
            user_id TEXT PRIMARY KEY,
            preferred_platform TEXT,
            preferred_style TEXT,
            preferred_duration TEXT,
            content_preferences TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # 創建生成內容表
    execute_sql("""
        CREATE TABLE IF NOT EXISTS generations (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            content TEXT,
            platform TEXT,
            topic TEXT,
            dedup_hash TEXT UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES user_profiles (user_id)
        )
    """)
    
    # 創建對話摘要表
    execute_sql("""
        CREATE TABLE IF NOT EXISTS conversation_summaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            summary TEXT NOT NULL,
            conversation_type TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES user_profiles (user_id)
        )
    """)
    
    # 兼容舊表：補齊缺少欄位（message_count, updated_at）
    try:
        execute_sql("""
            ALTER TABLE conversation_summaries ADD COLUMN message_count INTEGER DEFAULT 0
        """)
    except Exception as e:
        # 欄位已存在則略過（SQLite/PG 不同錯誤訊息，這裡容錯）
        pass
    try:
        execute_sql("""
            ALTER TABLE conversation_summaries ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        """)
    except Exception as e:
        pass
    
    # 創建用戶偏好追蹤表
    execute_sql("""
        CREATE TABLE IF NOT EXISTS user_preferences (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            preference_type TEXT NOT NULL,
            preference_value TEXT NOT NULL,
            confidence_score REAL DEFAULT 1.0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES user_profiles (user_id),
            UNIQUE(user_id, preference_type)
        )
    """)
    
    # 創建用戶行為記錄表
    execute_sql("""
        CREATE TABLE IF NOT EXISTS user_behaviors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            behavior_type TEXT NOT NULL,
            behavior_data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES user_profiles (user_id)
        )
    """)
    
    # 創建用戶認證表
    execute_sql("""
        CREATE TABLE IF NOT EXISTS user_auth (
            user_id TEXT PRIMARY KEY,
            google_id TEXT UNIQUE,
            email TEXT UNIQUE,
            name TEXT,
            picture TEXT,
            access_token TEXT,
            refresh_token TEXT,
            expires_at TIMESTAMP,
            is_subscribed INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # 為現有用戶添加 is_subscribed 欄位（如果不存在）
    try:
        cursor.execute("ALTER TABLE user_auth ADD COLUMN is_subscribed INTEGER DEFAULT 1")
        print("INFO: 已新增 is_subscribed 欄位到 user_auth 表")
    except (sqlite3.OperationalError, Exception) as e:
        # 兼容 SQLite 和 PostgreSQL 的錯誤
        error_str = str(e).lower()
        if "duplicate column" in error_str or "already exists" in error_str:
            print("INFO: 欄位 is_subscribed 已存在，跳過新增")
        else:
            print(f"WARNING: 無法新增 is_subscribed 欄位: {e}")
    
    # 將所有現有用戶的訂閱狀態設為 1（已訂閱）
    try:
        cursor.execute("UPDATE user_auth SET is_subscribed = 1 WHERE is_subscribed IS NULL OR is_subscribed = 0")
        updated_count = cursor.rowcount
        if updated_count > 0:
            print(f"INFO: 已將 {updated_count} 個用戶設為已訂閱")
    except Exception as e:
        print(f"INFO: 更新訂閱狀態時出現錯誤（可能是表格為空）: {e}")
    
    # 創建帳號定位記錄表
    execute_sql("""
        CREATE TABLE IF NOT EXISTS positioning_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            record_number TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES user_profiles (user_id)
        )
    """)
    
    # 創建腳本儲存表
    execute_sql("""
        CREATE TABLE IF NOT EXISTS user_scripts (
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
        )
    """)
    
    # 創建用戶 LLM API Key 表 (BYOK)
    execute_sql("""
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
    """)
    
    # 創建 IP 人設規劃結果表
    execute_sql("""
        CREATE TABLE IF NOT EXISTS ip_planning_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            result_type TEXT NOT NULL,
            title TEXT,
            content TEXT NOT NULL,
            metadata TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES user_profiles (user_id)
        )
    """)
    
    # 創建購買訂單表（orders）
    execute_sql("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            order_id TEXT UNIQUE NOT NULL,
            plan_type TEXT NOT NULL,
            amount INTEGER NOT NULL,
            currency TEXT DEFAULT 'TWD',
            payment_method TEXT,
            payment_status TEXT DEFAULT 'pending',
            paid_at TIMESTAMP,
            expires_at TIMESTAMP,
            invoice_number TEXT,
            invoice_type TEXT,
            vat_number TEXT,
            name TEXT,
            email TEXT,
            phone TEXT,
            note TEXT,
            trade_no TEXT,
            expire_date TIMESTAMP,
            payment_code TEXT,
            bank_code TEXT,
            raw_payload TEXT,
            raw_data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # 檢查並新增缺失的欄位（向後兼容）
    try:
        if use_postgresql:
            # PostgreSQL: 檢查欄位是否存在
            new_columns = [
                ('vat_number', 'TEXT'),
                ('name', 'TEXT'),
                ('email', 'TEXT'),
                ('phone', 'TEXT'),
                ('note', 'TEXT'),
                ('trade_no', 'TEXT'),
                ('expire_date', 'TIMESTAMP'),
                ('payment_code', 'TEXT'),
                ('bank_code', 'TEXT'),
                ('raw_payload', 'TEXT')
            ]
            
            for col_name, col_type in new_columns:
                cursor.execute("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name = 'orders' AND column_name = %s
                """, (col_name,))
                if not cursor.fetchone():
                    try:
                        cursor.execute(f"ALTER TABLE orders ADD COLUMN {col_name} {col_type}")
                        print(f"INFO: 已新增欄位 orders.{col_name}")
                    except Exception as e:
                        print(f"WARN: 新增欄位 orders.{col_name} 失敗: {e}")
        else:
            # SQLite: 檢查欄位是否存在
            cursor.execute("PRAGMA table_info(orders)")
            existing_columns = [col[1] for col in cursor.fetchall()]
            
            new_columns = [
                ('vat_number', 'TEXT'),
                ('name', 'TEXT'),
                ('email', 'TEXT'),
                ('phone', 'TEXT'),
                ('note', 'TEXT'),
                ('trade_no', 'TEXT'),
                ('expire_date', 'TIMESTAMP'),
                ('payment_code', 'TEXT'),
                ('bank_code', 'TEXT'),
                ('raw_payload', 'TEXT')
            ]
            
            for col_name, col_type in new_columns:
                if col_name not in existing_columns:
                    try:
                        cursor.execute(f"ALTER TABLE orders ADD COLUMN {col_name} {col_type}")
                        print(f"INFO: 已新增欄位 orders.{col_name}")
                    except Exception as e:
                        print(f"WARN: 新增欄位 orders.{col_name} 失敗: {e}")
    except Exception as e:
        print(f"WARN: 檢查 orders 表結構時出錯: {e}")
    
    # 創建授權啟用表（license_activations）
    execute_sql("""
        CREATE TABLE IF NOT EXISTS license_activations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            activation_token TEXT UNIQUE NOT NULL,
            channel TEXT NOT NULL,
            order_id TEXT NOT NULL,
            email TEXT NOT NULL,
            plan_type TEXT NOT NULL,
            amount INTEGER NOT NULL,
            status TEXT DEFAULT 'pending',
            activated_at TIMESTAMP,
            activated_by_user_id TEXT,
            link_expires_at TIMESTAMP,
            license_expires_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # 創建管理員帳號表
    execute_sql("""
        CREATE TABLE IF NOT EXISTS admin_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # 初始化管理員帳號（如果不存在）
    try:
        admin_email = "aiagentg888@gmail.com"
        admin_password_hash = "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9"  # admin123 的 SHA256
        if use_postgresql:
            cursor.execute("""
                INSERT INTO admin_accounts (email, password_hash, name, is_active)
                VALUES (%s, %s, %s, 1)
                ON CONFLICT (email) DO NOTHING
            """, (admin_email, admin_password_hash, "管理員"))
        else:
            cursor.execute("""
                INSERT OR IGNORE INTO admin_accounts (email, password_hash, name, is_active)
                VALUES (?, ?, ?, 1)
            """, (admin_email, admin_password_hash, "管理員"))
        conn.commit()
        print(f"INFO: 管理員帳號已初始化: {admin_email}")
    except Exception as e:
        print(f"INFO: 管理員帳號初始化時出現錯誤（可能是已存在）: {e}")
        try:
            conn.rollback()
        except:
            pass
    
    # 創建長期記憶對話表（Long Term Memory）
    execute_sql("""
        CREATE TABLE IF NOT EXISTS long_term_memory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            conversation_type TEXT NOT NULL,
            session_id TEXT,
            message_role TEXT NOT NULL,
            message_content TEXT NOT NULL,
            metadata TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES user_auth (user_id)
        )
    """)
    
    # 創建AI顧問對話記錄表
    execute_sql("""
        CREATE TABLE IF NOT EXISTS ai_advisor_chats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            message_role TEXT NOT NULL,
            message_content TEXT NOT NULL,
            platform TEXT,
            topic TEXT,
            style TEXT,
            duration TEXT,
            metadata TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES user_auth (user_id)
        )
    """)
    
    # 創建IP人設規劃對話記錄表
    execute_sql("""
        CREATE TABLE IF NOT EXISTS ip_planning_chats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            message_role TEXT NOT NULL,
            message_content TEXT NOT NULL,
            positioning_type TEXT,
            target_audience TEXT,
            content_style TEXT,
            metadata TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES user_auth (user_id)
        )
    """)
    
    # 創建LLM對話記錄表
    execute_sql("""
        CREATE TABLE IF NOT EXISTS llm_conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            message_role TEXT NOT NULL,
            message_content TEXT NOT NULL,
            conversation_context TEXT,
            model_used TEXT,
            metadata TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES user_auth (user_id)
        )
    """)
    
    # 創建授權記錄表（licenses）
    execute_sql("""
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL UNIQUE,
            order_id TEXT,
            tier TEXT DEFAULT 'personal',
            seats INTEGER DEFAULT 1,
            features_json TEXT,
            source TEXT,
            start_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # 為已存在的 licenses 表添加 UNIQUE 約束（如果不存在）
    # 這對已存在的表進行遷移
    if use_postgresql:
        try:
            # PostgreSQL: 檢查約束是否存在，不存在則添加
            cursor.execute("""
                SELECT constraint_name 
                FROM information_schema.table_constraints 
                WHERE table_name = 'licenses' 
                AND constraint_type = 'UNIQUE' 
                AND constraint_name LIKE '%user_id%'
            """)
            if not cursor.fetchone():
                try:
                    cursor.execute("ALTER TABLE licenses ADD CONSTRAINT licenses_user_id_unique UNIQUE (user_id)")
                    print("INFO: 已為 licenses 表添加 user_id UNIQUE 約束")
                except Exception as e:
                    # 約束可能已存在或表不存在
                    print(f"INFO: licenses.user_id UNIQUE 約束可能已存在或無法添加: {e}")
        except Exception as e:
            print(f"INFO: 檢查 licenses UNIQUE 約束時出錯（可忽略）: {e}")
    else:
        # SQLite: 創建唯一索引（如果不存在）
        try:
            cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS licenses_user_id_unique ON licenses(user_id)")
        except Exception as e:
            print(f"INFO: licenses.user_id 唯一索引可能已存在: {e}")
    
    # PostgreSQL 使用 AUTOCOMMIT，不需要 commit
    # SQLite 需要 commit
    if not use_postgresql:
        conn.commit()
        conn.close()
    
    if use_postgresql:
        conn.close()
        return "PostgreSQL"
    else:
        return db_path


def get_db_connection():
    """獲取數據庫連接（支援 PostgreSQL 和 SQLite）"""
    database_url = os.getenv("DATABASE_URL")
    
    # 如果有 DATABASE_URL 且包含 postgresql://，使用 PostgreSQL
    if database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE:
        try:
            print(f"INFO: 連接到 PostgreSQL 資料庫")
            conn = psycopg2.connect(database_url)
            conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
            return conn
        except Exception as e:
            print(f"ERROR: PostgreSQL 連接失敗: {e}")
            raise
    
    # 預設使用 SQLite
    db_dir = os.getenv("DATABASE_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))
    db_path = os.path.join(db_dir, "chatbot.db")
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    
    print(f"INFO: 連接到 SQLite 資料庫: {db_path}")
    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def generate_dedup_hash(content: str, platform: str = None, topic: str = None) -> str:
    """生成去重哈希值"""
    # 清理內容，移除時間相關和隨機元素
    clean_content = content.lower().strip()
    # 移除常見的時間標記和隨機元素
    clean_content = clean_content.replace('\n', ' ').replace('\r', ' ')
    # 移除多餘空格
    clean_content = ' '.join(clean_content.split())
    
    hash_input = f"{clean_content}|{platform or ''}|{topic or ''}"
    return hashlib.md5(hash_input.encode('utf-8')).hexdigest()


def generate_user_id(email: str) -> str:
    """根據 email 生成用戶 ID"""
    return hashlib.md5(email.encode('utf-8')).hexdigest()[:12]


# ===== ECPay 金流功能 =====

def gen_check_mac_value(params: dict) -> str:
    """生成 ECPay 簽章（CheckMacValue）
    
    Args:
        params: 包含所有參數的字典（不包含 CheckMacValue）
    
    Returns:
        簽章字串（大寫）
    """
    if not ECPAY_HASH_KEY or not ECPAY_HASH_IV:
        raise ValueError("ECPAY_HASH_KEY 或 ECPAY_HASH_IV 未設定")
    
    # 移除 CheckMacValue（如果存在）
    items = [(k, str(v)) for k, v in params.items() if k != "CheckMacValue" and v is not None]
    # 按照參數名稱排序
    items.sort(key=lambda x: x[0])
    # 組合成查詢字串
    query = "&".join([f"{k}={v}" for k, v in items])
    # 組合原始字串
    raw = f"HashKey={ECPAY_HASH_KEY}&{query}&HashIV={ECPAY_HASH_IV}"
    # URL 編碼並轉小寫，將 %20 替換為 +
    import urllib.parse
    urlencoded = urllib.parse.quote(raw, safe="()!*").lower().replace("%20", "+")
    # SHA256 雜湊並轉大寫
    return hashlib.sha256(urlencoded.encode("utf-8")).hexdigest().upper()


def verify_ecpay_signature(params: dict) -> bool:
    """驗證 ECPay 簽章
    
    Args:
        params: 包含 CheckMacValue 的參數字典
    
    Returns:
        驗證是否通過
    """
    try:
        received_signature = params.get("CheckMacValue", "")
        expected_signature = gen_check_mac_value(params)
        return received_signature == expected_signature
    except Exception as e:
        print(f"ERROR: 驗證 ECPay 簽章失敗: {e}")
        return False


def is_ecpay_ip(ip_address: str) -> bool:
    """檢查 IP 是否在 ECPay 白名單中（完整實作）
    
    使用 ipaddress 模組檢查 IP 是否在設定的 IP 範圍內。
    
    Args:
        ip_address: 客戶端 IP 地址
    
    Returns:
        是否在白名單中
    """
    if not ip_address:
        return False
    
    # 如果白名單為空，記錄警告但允許通過（測試環境）
    if not ECPAY_IP_WHITELIST:
        logger.warning("ECPAY_IP_WHITELIST 未設定，允許所有 IP（僅測試環境）")
        return True
    
    try:
        # 解析客戶端 IP
        client_ip = ipaddress.ip_address(ip_address)
        
        # 檢查是否在任何一個白名單範圍內
        for ip_range_str in ECPAY_IP_WHITELIST:
            try:
                ip_range = ipaddress.ip_network(ip_range_str, strict=False)
                if client_ip in ip_range:
                    logger.info(f"IP {ip_address} 在白名單範圍 {ip_range_str} 內")
                    return True
            except ValueError as e:
                logger.warning(f"無效的 IP 範圍格式: {ip_range_str}, 錯誤: {e}")
                continue
        
        # 如果都不在範圍內，記錄警告
        logger.warning(f"IP {ip_address} 不在 ECPay 白名單內，白名單: {ECPAY_IP_WHITELIST}")
        return False
    
    except ValueError as e:
        logger.error(f"無效的 IP 地址格式: {ip_address}, 錯誤: {e}")
        return False


# ===== 輸入驗證函數 =====

def validate_api_key(api_key: str, provider: str) -> bool:
    """驗證 API Key 格式
    
    Args:
        api_key: API Key 字串
        provider: 提供商（'gemini' 或 'openai'）
    
    Returns:
        是否有效
    """
    if not api_key or not isinstance(api_key, str):
        return False
    
    # 長度限制
    if len(api_key) > 500:
        return False
    
    # 根據提供商驗證格式
    if provider == "gemini":
        # Gemini API Key 通常是 "AIzaSy..." 開頭，32-39 字符
        if not api_key.startswith("AIzaSy") or len(api_key) < 32 or len(api_key) > 39:
            return False
    elif provider == "openai":
        # OpenAI API Key 通常是 "sk-" 開頭
        if not api_key.startswith("sk-") or len(api_key) < 20:
            return False
    
    # 只允許字母、數字、連字號、底線
    if not re.match(r'^[A-Za-z0-9_-]+$', api_key):
        return False
    
    return True


def validate_user_id(user_id: str) -> bool:
    """驗證用戶 ID 格式
    
    Args:
        user_id: 用戶 ID 字串
    
    Returns:
        是否有效
    """
    if not user_id or not isinstance(user_id, str):
        return False
    
    # 長度限制
    if len(user_id) > 50:
        return False
    
    # 只允許字母、數字、連字號、底線
    if not re.match(r'^[a-zA-Z0-9_-]+$', user_id):
        return False
    
    return True


def validate_email(email: str) -> bool:
    """驗證 Email 格式
    
    Args:
        email: Email 字串
    
    Returns:
        是否有效
    """
    if not email or not isinstance(email, str):
        return False
    
    # 長度限制
    if len(email) > 255:
        return False
    
    # 基本 Email 格式驗證
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_pattern, email))


# ===== ECPay 發票開立功能 =====

async def issue_ecpay_invoice(
    trade_no: str,
    amount: int,
    invoice_type: str,
    vat_number: Optional[str] = None,
    user_id: Optional[str] = None
) -> Optional[str]:
    """開立 ECPay 電子發票
    
    Args:
        trade_no: 訂單號
        amount: 金額
        invoice_type: 發票類型（'personal' 或 'company'）
        vat_number: 統編（公司發票必填）
        user_id: 用戶 ID（用於查詢用戶資訊）
    
    Returns:
        發票號碼，失敗返回 None
    """
    if not ECPAY_INVOICE_ENABLED:
        logger.info("發票功能未啟用")
        return None
    
    if not ECPAY_INVOICE_MERCHANT_ID:
        logger.warning("ECPAY_INVOICE_MERCHANT_ID 未設定，無法開立發票")
        return None
    
    try:
        # 查詢用戶資訊（Email、姓名）
        conn = get_db_connection()
        cursor = conn.cursor()
        
        database_url = os.getenv("DATABASE_URL")
        use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
        
        email = ""
        name = ""
        if user_id:
            if use_postgresql:
                cursor.execute(
                    "SELECT email, name FROM user_auth WHERE user_id = %s",
                    (user_id,)
                )
            else:
                cursor.execute(
                    "SELECT email, name FROM user_auth WHERE user_id = ?",
                    (user_id,)
                )
            
            user_info = cursor.fetchone()
            if user_info:
                email = user_info[0] or ""
                name = user_info[1] or ""
        
        cursor.close()
        conn.close()
        
        # 準備發票參數
        invoice_data = {
            "MerchantID": ECPAY_INVOICE_MERCHANT_ID,
            "RelateNumber": trade_no,  # 關聯訂單號
            "InvoiceDate": get_taiwan_time().strftime("%Y/%m/%d %H:%M:%S"),
            "InvoiceType": "07",  # 一般稅額
            "TaxType": "1",  # 應稅
            "SalesAmount": amount,
            "Items": json.dumps([{
                "ItemName": f"ReelMind 訂閱方案",
                "ItemCount": 1,
                "ItemWord": "次",
                "ItemPrice": amount,
                "ItemTaxType": "1",
                "ItemAmount": amount
            }]),
        }
        
        # 根據發票類型設定
        if invoice_type == "company" and vat_number:
            # 公司發票（三聯式）
            invoice_data["CustomerIdentifier"] = vat_number
            invoice_data["Print"] = "0"  # 不列印
        else:
            # 個人發票（二聯式）
            invoice_data["CustomerEmail"] = email
            invoice_data["Print"] = "0"
        
        # 生成簽章
        invoice_data["CheckMacValue"] = gen_check_mac_value(invoice_data)
        
        # 呼叫 ECPay 發票 API
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                ECPAY_INVOICE_API,
                data=invoice_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if response.status_code == 200:
                # 解析回應（ECPay 返回格式：RtnCode|RtnMsg|InvoiceNo|...）
                response_text = response.text
                parts = response_text.split("|")
                
                if len(parts) >= 3 and parts[0] == "1":
                    invoice_number = parts[2]  # 發票號碼
                    logger.info(f"發票開立成功: {invoice_number}")
                    return invoice_number
                else:
                    error_msg = parts[1] if len(parts) > 1 else "未知錯誤"
                    logger.error(f"發票開立失敗: {error_msg}, 回應: {response_text}")
                    return None
            else:
                logger.error(f"發票 API 請求失敗: HTTP {response.status_code}")
                return None
    
    except Exception as e:
        logger.error(f"開立發票異常: {e}", exc_info=True)
        return None


# ===== ECPay 退款處理功能 =====

async def process_ecpay_refund(
    trade_no: str,
    refund_amount: Optional[int] = None,
    refund_reason: Optional[str] = None
) -> Dict[str, Any]:
    """處理 ECPay 退款
    
    Args:
        trade_no: 訂單號
        refund_amount: 退款金額（None 表示全額退款）
        refund_reason: 退款原因
    
    Returns:
        退款結果字典
    """
    try:
        # 查詢訂單資訊
        conn = get_db_connection()
        cursor = conn.cursor()
        
        database_url = os.getenv("DATABASE_URL")
        use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
        
        if use_postgresql:
            cursor.execute(
                "SELECT amount, payment_status, invoice_number FROM orders WHERE order_id = %s",
                (trade_no,)
            )
        else:
            cursor.execute(
                "SELECT amount, payment_status, invoice_number FROM orders WHERE order_id = ?",
                (trade_no,)
            )
        
        order = cursor.fetchone()
        
        if not order:
            cursor.close()
            conn.close()
            return {"success": False, "error": "訂單不存在"}
        
        amount, payment_status, invoice_number = order
        
        # 檢查訂單狀態
        if payment_status != "paid":
            cursor.close()
            conn.close()
            return {"success": False, "error": f"訂單狀態不允許退款: {payment_status}"}
        
        # 確定退款金額
        if refund_amount is None:
            refund_amount = amount
        elif refund_amount > amount:
            cursor.close()
            conn.close()
            return {"success": False, "error": "退款金額不能超過訂單金額"}
        
        # 如果有發票，需要作廢發票
        if invoice_number and ECPAY_INVOICE_ENABLED:
            # 先作廢發票
            invoice_void_result = await void_ecpay_invoice(invoice_number, trade_no)
            if not invoice_void_result.get("success"):
                logger.warning(f"發票作廢失敗: {invoice_void_result.get('error')}")
        
        # 準備退款參數
        refund_data = {
            "MerchantID": ECPAY_MERCHANT_ID,
            "MerchantTradeNo": trade_no,
            "TradeNo": "",  # ECPay 交易序號（需要從訂單記錄中取得）
            "Action": "R",  # Refund
            "TotalAmount": refund_amount,
        }
        
        # 生成簽章
        refund_data["CheckMacValue"] = gen_check_mac_value(refund_data)
        
        # 呼叫 ECPay 退款 API
        refund_api = ECPAY_API.replace("/Cashier/AioCheckOut/V5", "/Cashier/QueryTradeInfo/V5")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                refund_api,
                data=refund_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if response.status_code == 200:
                response_text = response.text
                # 解析回應
                if "RtnCode=1" in response_text:
                    # 更新訂單狀態
                    if use_postgresql:
                        cursor.execute("""
                            UPDATE orders 
                            SET payment_status = %s,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE order_id = %s
                        """, ("refunded", trade_no))
                    else:
                        cursor.execute("""
                            UPDATE orders 
                            SET payment_status = ?,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE order_id = ?
                        """, ("refunded", trade_no))
                    
                    conn.commit()
                    cursor.close()
                    conn.close()
                    
                    logger.info(f"退款成功，訂單號: {trade_no}, 金額: {refund_amount}")
                    return {"success": True, "refund_amount": refund_amount}
                else:
                    cursor.close()
                    conn.close()
                    error_msg = response_text
                    logger.error(f"退款失敗: {error_msg}")
                    return {"success": False, "error": error_msg}
            else:
                cursor.close()
                conn.close()
                logger.error(f"退款 API 請求失敗: HTTP {response.status_code}")
                return {"success": False, "error": f"HTTP {response.status_code}"}
    
    except Exception as e:
        logger.error(f"退款處理異常: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


async def void_ecpay_invoice(invoice_number: str, trade_no: str) -> Dict[str, Any]:
    """作廢 ECPay 電子發票
    
    Args:
        invoice_number: 發票號碼
        trade_no: 訂單號
    
    Returns:
        作廢結果字典
    """
    try:
        void_data = {
            "MerchantID": ECPAY_INVOICE_MERCHANT_ID,
            "InvoiceNumber": invoice_number,
            "VoidReason": "訂單退款",
        }
        
        void_data["CheckMacValue"] = gen_check_mac_value(void_data)
        
        void_api = ECPAY_INVOICE_API.replace("/Invoice/Issue", "/Invoice/Invalid")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                void_api,
                data=void_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if response.status_code == 200:
                response_text = response.text
                parts = response_text.split("|")
                
                if len(parts) >= 2 and parts[0] == "1":
                    return {"success": True}
                else:
                    error_msg = parts[1] if len(parts) > 1 else "未知錯誤"
                    return {"success": False, "error": error_msg}
            else:
                return {"success": False, "error": f"HTTP {response.status_code}"}
    
    except Exception as e:
        logger.error(f"作廢發票異常: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


def generate_access_token(user_id: str) -> str:
    """生成訪問令牌（使用標準 PyJWT 庫）"""
    if JWT_AVAILABLE:
        # 使用標準 PyJWT 庫
        payload = {
            "user_id": user_id,
            "exp": get_taiwan_time().timestamp() + 86400  # 24小時過期
        }
        return jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    else:
        # 回退到舊的實現（不建議，但保持向後兼容）
        payload = {
            "user_id": user_id,
            "exp": get_taiwan_time().timestamp() + 86400  # 24小時過期
        }
        import json
    header = {"alg": "HS256", "typ": "JWT"}
    encoded_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    signature = hashlib.sha256(f"{encoded_header}.{encoded_payload}.{JWT_SECRET}".encode()).hexdigest()
    return f"{encoded_header}.{encoded_payload}.{signature}"


def verify_access_token(token: str, allow_expired: bool = False) -> Optional[str]:
    """驗證訪問令牌並返回用戶 ID（使用標準 PyJWT 庫）
    
    Args:
        token: JWT token
        allow_expired: 如果為 True，允許過期的 token（用於 refresh 場景）
    """
    if JWT_AVAILABLE:
        # 使用標準 PyJWT 庫
        try:
            options = {"verify_exp": not allow_expired}
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"], options=options)
            return payload.get("user_id")
        except jwt.ExpiredSignatureError:
            if allow_expired:
                # 如果允許過期，嘗試解碼但不驗證過期時間
                try:
                    payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"], options={"verify_exp": False})
                    return payload.get("user_id")
                except jwt.InvalidTokenError:
                    return None
            return None
        except jwt.InvalidTokenError:
            return None
    else:
        # 回退到舊的實現（不建議，但保持向後兼容）
        try:
            import json
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            # 驗證簽名
            expected_signature = hashlib.sha256(f"{parts[0]}.{parts[1]}.{JWT_SECRET}".encode()).hexdigest()
            if expected_signature != parts[2]:
                return None
            
            # 解碼 payload（處理 base64 填充）
            payload_str = parts[1]
            # 添加必要的填充
            padding = 4 - len(payload_str) % 4
            if padding != 4:
                payload_str += '=' * padding
            
            payload = json.loads(base64.urlsafe_b64decode(payload_str).decode())
            
            # 檢查過期時間（如果 allow_expired=False）
            if not allow_expired:
                exp = payload.get("exp", 0)
                now = get_taiwan_time().timestamp()
                if exp < now:
                    return None
            
            return payload.get("user_id")
        except Exception as e:
            return None


async def get_google_user_info(access_token: str) -> Optional[GoogleUser]:
    """從 Google 獲取用戶資訊"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            if response.status_code == 200:
                data = response.json()
                return GoogleUser(
                    id=data["id"],
                    email=data["email"],
                    name=data["name"],
                    picture=data.get("picture"),
                    verified_email=data.get("verified_email", False)
                )
    except Exception as e:
        print(f"Error getting Google user info: {e}")
    return None


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Optional[str]:
    """獲取當前用戶 ID"""
    if not credentials:
        print("DEBUG: get_current_user - 沒有 credentials")
        return None
    token = credentials.credentials
    user_id = verify_access_token(token)
    if not user_id:
        print(f"DEBUG: get_current_user - token 驗證失敗，token 前20個字符: {token[:20] if token else 'None'}")
    else:
        print(f"DEBUG: get_current_user - 成功驗證，user_id: {user_id}")
    return user_id

async def get_current_user_for_refresh(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Optional[str]:
    """獲取當前用戶 ID（允許過期的 token，用於 refresh 場景）"""
    if not credentials:
        print("DEBUG: get_current_user_for_refresh - 沒有 credentials")
        return None
    token = credentials.credentials
    user_id = verify_access_token(token, allow_expired=True)
    if not user_id:
        print(f"DEBUG: get_current_user_for_refresh - token 驗證失敗，token 前10個字符: {token[:10] if token else 'None'}")
    else:
        print(f"DEBUG: get_current_user_for_refresh - 成功驗證，user_id: {user_id}")
    return user_id


async def get_admin_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Optional[str]:
    """驗證並返回管理員用戶 ID。
    支援兩種方式判斷管理員：
    1. 透過環境變數 ADMIN_USER_IDS（以逗號分隔的 user_id 列表）
    2. 透過環境變數 ADMIN_EMAILS（以逗號分隔的 email 列表）
    3. 透過資料庫 admin_accounts 表檢查
    """
    user_id = await get_current_user(credentials)
    if not user_id:
        raise HTTPException(status_code=401, detail="未授權")
    
    # 方式 1: 檢查 user_id 是否在白名單中
    admin_ids = os.getenv("ADMIN_USER_IDS", "").split(",")
    admin_ids = [x.strip() for x in admin_ids if x.strip()]
    if user_id in admin_ids:
        return user_id
    
    # 方式 2: 檢查 email 是否在白名單中
    admin_emails = os.getenv("ADMIN_EMAILS", "").split(",")
    admin_emails = [x.strip().lower() for x in admin_emails if x.strip()]
    
    # 從資料庫獲取用戶 email
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        database_url = os.getenv("DATABASE_URL")
        use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
        
        if use_postgresql:
            cursor.execute("SELECT email FROM user_auth WHERE user_id = %s", (user_id,))
        else:
            cursor.execute("SELECT email FROM user_auth WHERE user_id = ?", (user_id,))
        result = cursor.fetchone()
        conn.close()
        
        if result and result[0]:
            user_email = result[0].lower()
            # 檢查 email 是否在白名單中
            if user_email in admin_emails:
                return user_id
            
            # 方式 3: 檢查是否在 admin_accounts 表中
            conn = get_db_connection()
            cursor = conn.cursor()
            if use_postgresql:
                cursor.execute("SELECT id FROM admin_accounts WHERE email = %s AND is_active = 1", (user_email,))
            else:
                cursor.execute("SELECT id FROM admin_accounts WHERE email = ? AND is_active = 1", (user_email,))
            admin_account = cursor.fetchone()
            conn.close()
            
            if admin_account:
                return user_id
    except Exception as e:
        print(f"檢查管理員權限時出錯: {e}")
    
    raise HTTPException(status_code=403, detail="無管理員權限")


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


def save_conversation_summary(user_id: str, user_message: str, ai_response: str) -> None:
    """保存智能對話摘要"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        database_url = os.getenv("DATABASE_URL")
        use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE

        # 確保 user_profiles 存在該 user_id（修復外鍵約束錯誤）
        if use_postgresql:
            cursor.execute("SELECT user_id FROM user_profiles WHERE user_id = %s", (user_id,))
        else:
            cursor.execute("SELECT user_id FROM user_profiles WHERE user_id = ?", (user_id,))
        
        if not cursor.fetchone():
            # 如果不存在，自動創建
            if use_postgresql:
                cursor.execute("""
                    INSERT INTO user_profiles (user_id, created_at)
                    VALUES (%s, CURRENT_TIMESTAMP)
                    ON CONFLICT (user_id) DO NOTHING
                """, (user_id,))
            else:
                cursor.execute("""
                    INSERT OR IGNORE INTO user_profiles (user_id, created_at)
                    VALUES (?, CURRENT_TIMESTAMP)
                """, (user_id,))

        # 智能摘要生成
        summary = generate_smart_summary(user_message, ai_response)
        conversation_type = classify_conversation(user_message, ai_response)

        if use_postgresql:
            cursor.execute("""
                INSERT INTO conversation_summaries (user_id, summary, conversation_type, created_at)
                VALUES (%s, %s, %s, %s)
            """, (user_id, summary, conversation_type, get_taiwan_time()))
        else:
            cursor.execute("""
                INSERT INTO conversation_summaries (user_id, summary, conversation_type, created_at)
                VALUES (?, ?, ?, ?)
            """, (user_id, summary, conversation_type, get_taiwan_time()))

        # 追蹤用戶偏好
        track_user_preferences(user_id, user_message, ai_response, conversation_type)

        if not use_postgresql:
            conn.commit()
        conn.close()

    except Exception as e:
        print(f"保存對話摘要時出錯: {e}")

def track_user_preferences(user_id: str, user_message: str, ai_response: str, conversation_type: str) -> None:
    """追蹤用戶偏好"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        database_url = os.getenv("DATABASE_URL")
        use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
        
        # 提取偏好信息
        preferences = extract_user_preferences(user_message, ai_response, conversation_type)
        
        for pref_type, pref_value in preferences.items():
            # 檢查是否已存在
            if use_postgresql:
                cursor.execute("""
                    SELECT id, confidence_score FROM user_preferences 
                    WHERE user_id = %s AND preference_type = %s
                """, (user_id, pref_type))
            else:
                cursor.execute("""
                    SELECT id, confidence_score FROM user_preferences 
                    WHERE user_id = ? AND preference_type = ?
                """, (user_id, pref_type))
            
            existing = cursor.fetchone()
            
            if existing:
                # 更新現有偏好，增加信心分數
                new_confidence = min(existing[1] + 0.1, 1.0)
                if use_postgresql:
                    cursor.execute("""
                        UPDATE user_preferences 
                        SET preference_value = %s, confidence_score = %s, updated_at = %s
                        WHERE id = %s
                    """, (pref_value, new_confidence, get_taiwan_time(), existing[0]))
                else:
                    cursor.execute("""
                        UPDATE user_preferences 
                        SET preference_value = ?, confidence_score = ?, updated_at = ?
                        WHERE id = ?
                    """, (pref_value, new_confidence, get_taiwan_time(), existing[0]))
            else:
                # 創建新偏好
                if use_postgresql:
                    cursor.execute("""
                        INSERT INTO user_preferences (user_id, preference_type, preference_value, confidence_score)
                        VALUES (%s, %s, %s, %s)
                    """, (user_id, pref_type, pref_value, 0.5))
                else:
                    cursor.execute("""
                        INSERT INTO user_preferences (user_id, preference_type, preference_value, confidence_score)
                        VALUES (?, ?, ?, ?)
                    """, (user_id, pref_type, pref_value, 0.5))
        
        # 記錄行為
        if use_postgresql:
            cursor.execute("""
                INSERT INTO user_behaviors (user_id, behavior_type, behavior_data)
                VALUES (%s, %s, %s)
            """, (user_id, conversation_type, f"用戶輸入: {user_message[:100]}"))
        else:
            cursor.execute("""
                INSERT INTO user_behaviors (user_id, behavior_type, behavior_data)
                VALUES (?, ?, ?)
            """, (user_id, conversation_type, f"用戶輸入: {user_message[:100]}"))
        
        if not use_postgresql:
            conn.commit()
        conn.close()
        
    except Exception as e:
        print(f"追蹤用戶偏好時出錯: {e}")

def extract_user_preferences(user_message: str, ai_response: str, conversation_type: str) -> dict:
    """提取用戶偏好"""
    preferences = {}
    text = user_message.lower()
    
    # 平台偏好
    platforms = ["抖音", "tiktok", "instagram", "youtube", "小紅書", "快手"]
    for platform in platforms:
        if platform in text:
            preferences["preferred_platform"] = platform
            break
    
    # 內容類型偏好
    content_types = ["美食", "旅遊", "時尚", "科技", "教育", "娛樂", "生活", "健身"]
    for content_type in content_types:
        if content_type in text:
            preferences["preferred_content_type"] = content_type
            break
    
    # 風格偏好
    if "搞笑" in text or "幽默" in text:
        preferences["preferred_style"] = "搞笑幽默"
    elif "專業" in text or "教學" in text:
        preferences["preferred_style"] = "專業教學"
    elif "情感" in text or "溫馨" in text:
        preferences["preferred_style"] = "情感溫馨"
    
    # 時長偏好
    if "30秒" in text or "30s" in text:
        preferences["preferred_duration"] = "30秒"
    elif "60秒" in text or "60s" in text:
        preferences["preferred_duration"] = "60秒"
    elif "15秒" in text or "15s" in text:
        preferences["preferred_duration"] = "15秒"
    
    return preferences

def generate_smart_summary(user_message: str, ai_response: str) -> str:
    """生成智能對話摘要"""
    # 提取關鍵信息
    user_keywords = extract_keywords(user_message)
    ai_keywords = extract_keywords(ai_response)
    
    # 判斷對話類型
    conversation_type = classify_conversation(user_message, ai_response)
    
    # 生成摘要
    if conversation_type == "account_positioning":
        return f"帳號定位討論：{user_keywords} → {ai_keywords}"
    elif conversation_type == "topic_selection":
        return f"選題討論：{user_keywords} → {ai_keywords}"
    elif conversation_type == "script_generation":
        return f"腳本生成：{user_keywords} → {ai_keywords}"
    elif conversation_type == "general_consultation":
        return f"一般諮詢：{user_keywords} → {ai_keywords}"
    else:
        return f"對話：{user_message[:30]}... → {ai_response[:50]}..."

def extract_keywords(text: str) -> str:
    """提取關鍵詞"""
    # 簡單的關鍵詞提取
    keywords = []
    important_words = ["短影音", "腳本", "帳號", "定位", "選題", "平台", "內容", "創意", "爆款", "流量"]
    
    for word in important_words:
        if word in text:
            keywords.append(word)
    
    return "、".join(keywords[:3]) if keywords else "一般討論"

def classify_conversation(user_message: str, ai_response: str) -> str:
    """分類對話類型"""
    text = (user_message + " " + ai_response).lower()
    
    if any(word in text for word in ["帳號定位", "定位", "目標受眾", "受眾"]):
        return "account_positioning"
    elif any(word in text for word in ["選題", "主題", "熱點", "趨勢"]):
        return "topic_selection"
    elif any(word in text for word in ["腳本", "生成", "寫腳本", "製作腳本"]):
        return "script_generation"
    else:
        return "general_consultation"

def get_user_memory(user_id: Optional[str]) -> str:
    """獲取用戶的增強長期記憶和個人化資訊"""
    if not user_id:
        return ""

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        database_url = os.getenv("DATABASE_URL")
        use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE

        # 獲取用戶基本資料
        if use_postgresql:
            cursor.execute("SELECT * FROM user_profiles WHERE user_id = %s", (user_id,))
        else:
            cursor.execute("SELECT * FROM user_profiles WHERE user_id = ?", (user_id,))
        profile = cursor.fetchone()

        # 獲取用戶偏好
        if use_postgresql:
            cursor.execute("""
                SELECT preference_type, preference_value, confidence_score 
                FROM user_preferences 
                WHERE user_id = %s AND confidence_score > 0.3
                ORDER BY confidence_score DESC
            """, (user_id,))
        else:
            cursor.execute("""
                SELECT preference_type, preference_value, confidence_score 
                FROM user_preferences 
                WHERE user_id = ? AND confidence_score > 0.3
                ORDER BY confidence_score DESC
            """, (user_id,))
        preferences = cursor.fetchall()

        # 獲取最近的對話摘要（按類型分組）
        if use_postgresql:
            cursor.execute("""
                SELECT conversation_type, summary, created_at 
                FROM conversation_summaries
                WHERE user_id = %s
                ORDER BY created_at DESC
                LIMIT 10
            """, (user_id,))
        else:
            cursor.execute("""
                SELECT conversation_type, summary, created_at 
                FROM conversation_summaries
                WHERE user_id = ?
                ORDER BY created_at DESC
                LIMIT 10
            """, (user_id,))
        summaries = cursor.fetchall()

        # 獲取最近的生成記錄
        if use_postgresql:
            cursor.execute("""
                SELECT platform, topic, content, created_at FROM generations
                WHERE user_id = %s
                ORDER BY created_at DESC
                LIMIT 5
            """, (user_id,))
        else:
            cursor.execute("""
                SELECT platform, topic, content, created_at FROM generations
                WHERE user_id = ?
                ORDER BY created_at DESC
                LIMIT 5
            """, (user_id,))
        generations = cursor.fetchall()

        # 獲取用戶行為統計
        if use_postgresql:
            cursor.execute("""
                SELECT behavior_type, COUNT(*) as count
                FROM user_behaviors
                WHERE user_id = %s
                GROUP BY behavior_type
                ORDER BY count DESC
            """, (user_id,))
        else:
            cursor.execute("""
                SELECT behavior_type, COUNT(*) as count
                FROM user_behaviors
                WHERE user_id = ?
                GROUP BY behavior_type
                ORDER BY count DESC
            """, (user_id,))
        behaviors = cursor.fetchall()

        # 獲取長期記憶（long_term_memory 表）- 新增
        if use_postgresql:
            cursor.execute("""
                SELECT conversation_type, session_id, message_role, message_content, created_at
                FROM long_term_memory
                WHERE user_id = %s
                ORDER BY created_at DESC
                LIMIT 50
            """, (user_id,))
        else:
            cursor.execute("""
                SELECT conversation_type, session_id, message_role, message_content, created_at
                FROM long_term_memory
                WHERE user_id = ?
                ORDER BY created_at DESC
                LIMIT 50
            """, (user_id,))
        long_term_memories = cursor.fetchall()

        conn.close()

        # 構建增強記憶內容
        memory_parts = []

        # 用戶基本資料
        if profile:
            memory_parts.append(f"用戶基本資料：{profile[2] if len(profile) > 2 else '無'}")

        # 用戶偏好
        if preferences:
            memory_parts.append("用戶偏好分析：")
            for pref_type, pref_value, confidence in preferences:
                confidence_text = "高" if confidence > 0.7 else "中" if confidence > 0.4 else "低"
                memory_parts.append(f"- {pref_type}：{pref_value} (信心度：{confidence_text})")

        # 對話摘要（按類型分組）
        if summaries:
            memory_parts.append("最近對話記錄：")
            current_type = None
            for conv_type, summary, created_at in summaries:
                if conv_type != current_type:
                    type_name = {
                        "account_positioning": "帳號定位討論",
                        "topic_selection": "選題討論", 
                        "script_generation": "腳本生成",
                        "general_consultation": "一般諮詢"
                    }.get(conv_type, "其他討論")
                    memory_parts.append(f"  {type_name}：")
                    current_type = conv_type
                memory_parts.append(f"    - {summary}")

        # 生成記錄
        if generations:
            memory_parts.append("最近生成內容：")
            for gen in generations:
                memory_parts.append(f"- 平台：{gen[0]}, 主題：{gen[1]}, 時間：{gen[3]}")

        # 行為統計
        if behaviors:
            memory_parts.append("用戶行為統計：")
            for behavior_type, count in behaviors:
                type_name = {
                    "account_positioning": "帳號定位",
                    "topic_selection": "選題討論",
                    "script_generation": "腳本生成",
                    "general_consultation": "一般諮詢"
                }.get(behavior_type, behavior_type)
                memory_parts.append(f"- {type_name}：{count}次")

        # 長期記憶對話內容（long_term_memory 表）- 新增
        if long_term_memories:
            memory_parts.append("長期記憶對話記錄：")
            # 按會話分組
            sessions = {}
            for conv_type, session_id, role, content, created_at in long_term_memories:
                if session_id not in sessions:
                    sessions[session_id] = {
                        "type": conv_type,
                        "messages": []
                    }
                # 限制每條訊息長度，避免過長
                content_preview = content[:200] + "..." if len(content) > 200 else content
                sessions[session_id]["messages"].append({
                    "role": role,
                    "content": content_preview
                })
            
            # 只顯示最近的幾個會話
            session_count = 0
            for session_id, session_data in list(sessions.items())[:5]:
                session_count += 1
                type_name = {
                    "ai_advisor": "AI顧問對話",
                    "ip_planning": "IP人設規劃",
                    "llm_chat": "LLM對話",
                    "script_generation": "腳本生成",
                    "general": "一般對話"
                }.get(session_data["type"], session_data["type"])
                memory_parts.append(f"  {type_name}會話 {session_count}：")
                # 只顯示最近的幾條訊息
                for msg in session_data["messages"][:3]:
                    role_name = "用戶" if msg["role"] == "user" else "AI"
                    memory_parts.append(f"    [{role_name}] {msg['content']}")

        return "\n".join(memory_parts) if memory_parts else ""

    except Exception as e:
        print(f"獲取用戶記憶時出錯: {e}")
        return ""

def build_system_prompt(kb_text: str, platform: Optional[str], profile: Optional[str], topic: Optional[str], style: Optional[str], duration: Optional[str], user_id: Optional[str] = None) -> str:
    # 檢查用戶是否真的設定了參數（不是預設值）
    platform_line = f"平台：{platform}" if platform else "平台：未設定"
    profile_line = f"帳號定位：{profile}" if profile else "帳號定位：未設定"
    topic_line = f"主題：{topic}" if topic else "主題：未設定"
    duration_line = f"腳本時長：{duration}秒" if duration else "腳本時長：未設定"
    # 獲取用戶記憶
    user_memory = get_user_memory(user_id)
    memory_header = "用戶記憶與個人化資訊：\n" if user_memory else ""
    kb_header = "短影音知識庫（節錄）：\n" if kb_text else ""
    rules = (
        "你是AIJob短影音顧問，專業協助用戶創作短影音內容。\n"
        "回答要口語化、簡潔有力，避免冗長問卷。\n"
        "優先依據知識庫回答，超出範圍可補充一般經驗並標示『[一般經驗]』。\n"
        "\n"
        "⚠️ 核心原則：\n"
        "1. 檢查對話歷史：用戶已經說過什麼？已經回答過什麼問題？\n"
        "2. 基於已有信息：如果用戶已經提供了受眾、產品、目標等信息，直接基於這些信息給建議，不要再問！\n"
        "3. 推進對話：每次回應都要讓對話往前進展，不要原地打轉或重複問題\n"
        "4. 記住流程位置：清楚知道現在是在帳號定位、選題還是腳本生成階段\n"
        "5. 避免問候語重複：如果不是對話開始，不要說「哈囉！很高興為您服務」之類的開場白\n"
        "\n"
        "專業顧問流程：\n"
        "1. 帳號定位階段：\n"
        "   - 收集：受眾是誰？產品/服務是什麼？目標是什麼？\n"
        "   - 當用戶已經說明這些，直接給出定位建議，不要再追問細節！\n"
        "   - 定位建議應包含：目標受眾分析、內容方向、風格調性\n"
        "\n"
        "2. 選題策略階段：\n"
        "   - 基於已確定的定位，推薦3-5個具體選題方向\n"
        "   - 不要再問定位相關問題\n"
        "\n"
        "3. 腳本生成階段：\n"
        "   - 只有在用戶明確要求時，才提供完整腳本\n"
        "\n"
        "對話記憶檢查清單：\n"
        "✅ 用戶是否已經說明受眾？→ 如果有，不要再問！\n"
        "✅ 用戶是否已經說明產品/目標？→ 如果有，不要再問！\n"
        "✅ 現在是對話開始還是中間？→ 如果是中間，不要用開場問候語！\n"
        "✅ 我已經收集到足夠信息了嗎？→ 如果有，給出具體建議，不要拖延！\n"
        "\n"
        "內容格式：\n"
        "• 使用數字標示（1. 2. 3.）或列點（•）組織內容\n"
        "• 用 emoji 分段強調（🚀 💡 ✅ 📌）\n"
        "• 絕對禁止使用 * 或 ** 等 Markdown 格式符號\n"
        "• 每段用換行分隔，保持清晰易讀\n"
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
    return f"{platform_line}\n{profile_line}\n{topic_line}\n{duration_line}\n{style_line}\n\n{rules}\n{memory_header}{user_memory}\n{kb_header}{kb_text}"


def create_app() -> FastAPI:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("WARNING: GEMINI_API_KEY not found in environment variables")
        # Delay failure to request time but keep app creatable
    else:
        print(f"INFO: GEMINI_API_KEY found, length: {len(api_key)}")

    genai.configure(api_key=api_key)
    model_name = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    print(f"INFO: Using model: {model_name}")

    # 初始化數據庫
    db_path = init_database()
    print(f"INFO: Database initialized at: {db_path}")

    app = FastAPI()

    # Rate Limiting 設定
    if SLOWAPI_AVAILABLE:
        limiter = Limiter(key_func=get_remote_address)
        app.state.limiter = limiter
        app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
        
        def rate_limit(limit_str: str):
            """Rate limiting 裝飾器"""
            return limiter.limit(limit_str)
    else:
        limiter = None
        
        def rate_limit(limit_str: str):
            """Rate limiting 裝飾器（未安裝 slowapi，返回空裝飾器）"""
            return lambda f: f

    # CORS for local file or dev servers
    frontend_url = os.getenv("FRONTEND_URL")
    cors_origins = [
        "http://localhost:5173",   # 本地前端（開發環境）
        "http://127.0.0.1:5173",  # 本地前端（備用）
        "http://localhost:8080",  # 本地測試
        "http://127.0.0.1:8080",  # 本地測試
        "https://aivideonew.zeabur.app",  # 生產環境前端
        "https://reelmind.aijob.com.tw",  # 生產環境前端
        "https://backmanage.zeabur.app",  # 後台管理系統
    ]
    
    # 如果有設定前端 URL，嚴格驗證後加入 CORS 來源
    if frontend_url:
        # 如果沒有協議前綴，自動添加 https://
        if not frontend_url.startswith("http://") and not frontend_url.startswith("https://"):
            frontend_url = f"https://{frontend_url}"
            print(f"INFO: FRONTEND_URL 自動添加 https:// 前綴: {frontend_url}")
        
        # 只允許 HTTPS（生產環境必須使用 HTTPS）
        if not frontend_url.startswith("https://"):
            # 開發環境允許 HTTP（localhost）
            if not frontend_url.startswith("http://localhost") and not frontend_url.startswith("http://127.0.0.1"):
                print(f"WARNING: FRONTEND_URL 必須使用 HTTPS: {frontend_url}")
            else:
                cors_origins.append(frontend_url)
        else:
            # 驗證域名格式
            parsed = urlparse(frontend_url)
            if not parsed.netloc or parsed.netloc.count('.') < 1:
                print(f"WARNING: FRONTEND_URL 格式錯誤: {frontend_url}")
            else:
                cors_origins.append(frontend_url)
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # 安全標頭中間件
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        """添加安全標頭"""
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # HSTS（只對 HTTPS 請求添加）
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    kb_text_cache = load_kb_text()

    @app.get("/")
    async def root():
        return {"message": "AI Video Backend is running"}
    
    @app.get("/api/debug/env")
    async def debug_env():
        """除錯環境變數"""
        return {
            "GOOGLE_CLIENT_ID": GOOGLE_CLIENT_ID,
            "GOOGLE_CLIENT_SECRET": "***" if GOOGLE_CLIENT_SECRET else None,
            "GOOGLE_REDIRECT_URI": GOOGLE_REDIRECT_URI,
            "GEMINI_API_KEY": "***" if os.getenv("GEMINI_API_KEY") else None,
            "GEMINI_MODEL": os.getenv("GEMINI_MODEL"),
            "FRONTEND_URL": os.getenv("FRONTEND_URL")
        }

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
                "timestamp": str(get_taiwan_time())
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "timestamp": str(get_taiwan_time())
            }

    @app.post("/api/generate/positioning")
    @rate_limit("10/minute")
    async def generate_positioning(body: ChatBody, request: Request):
        """一鍵生成帳號定位"""
        # 檢查是否有用戶自定義的 API Key
        user_id = getattr(body, 'user_id', None)
        user_api_key = get_user_llm_key(user_id, "gemini") if user_id else None
        
        # 如果沒有用戶的 API Key，使用系統預設的
        api_key = user_api_key or os.getenv("GEMINI_API_KEY")
        
        if not api_key:
            return JSONResponse({"error": "Missing GEMINI_API_KEY in .env"}, status_code=500)

        # 專門的帳號定位提示詞
        positioning_prompt = f"""
你是AIJob短影音顧問，專門協助用戶進行帳號定位分析。

基於以下信息進行專業的帳號定位分析：
- 平台：{body.platform or '未設定'}
- 主題：{body.topic or '未設定'}
- 現有定位：{body.profile or '未設定'}

請提供：
1. 目標受眾分析
2. 內容定位建議
3. 風格調性建議
4. 競爭優勢分析
5. 具體執行建議

格式要求：分段清楚，短句，每段換行，適度加入表情符號，避免口頭禪。絕對不要使用 ** 或任何 Markdown 格式符號。
"""

        try:
            # 暫時使用原有的 stream_chat 端點
            system_text = build_system_prompt(kb_text_cache, body.platform, body.profile, body.topic, body.style, body.duration, user_id)
            
            user_history: List[Dict[str, Any]] = []
            for m in body.history or []:
                user_history.append({"role": m.get("role", "user"), "parts": [m.get("content", "")]})

            # 使用用戶的 API Key 或系統預設的
            genai.configure(api_key=api_key)

            model_obj = genai.GenerativeModel(
                model_name=model_name,
                system_instruction=system_text
            )
            chat = model_obj.start_chat(history=user_history)

            async def generate():
                try:
                    stream_resp = chat.send_message(positioning_prompt, stream=True)
                    for chunk in stream_resp:
                        if chunk.text:
                            yield f"data: {json.dumps({'type': 'token', 'content': chunk.text})}\n\n"
                    
                    # 保存對話摘要
                    if user_id:
                        save_conversation_summary(user_id, positioning_prompt, "".join([c.text for c in stream_resp]))
                    
                    yield f"data: {json.dumps({'type': 'end'})}\n\n"
                except Exception as ex:
                    yield f"data: {json.dumps({'type': 'error', 'content': str(ex)})}\n\n"

            return StreamingResponse(generate(), media_type="text/plain")
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @app.post("/api/generate/topics")
    @rate_limit("10/minute")
    async def generate_topics(body: ChatBody, request: Request):
        """一鍵生成選題推薦"""
        # 檢查是否有用戶自定義的 API Key
        user_id = getattr(body, 'user_id', None)
        user_api_key = get_user_llm_key(user_id, "gemini") if user_id else None
        
        # 如果沒有用戶的 API Key，使用系統預設的
        api_key = user_api_key or os.getenv("GEMINI_API_KEY")
        
        if not api_key:
            return JSONResponse({"error": "Missing GEMINI_API_KEY in .env"}, status_code=500)

        # 專門的選題推薦提示詞
        topics_prompt = f"""
你是AIJob短影音顧問，專門協助用戶進行選題推薦。

基於以下信息推薦熱門選題：
- 平台：{body.platform or '未設定'}
- 主題：{body.topic or '未設定'}
- 帳號定位：{body.profile or '未設定'}

請提供：
1. 熱門選題方向（3-5個）
2. 每個選題的具體建議
3. 選題策略和技巧
4. 內容規劃建議
5. 執行時程建議

格式要求：分段清楚，短句，每段換行，適度加入表情符號，避免口頭禪。絕對不要使用 ** 或任何 Markdown 格式符號。
"""

        try:
            user_id = getattr(body, 'user_id', None)
            system_text = build_system_prompt(kb_text_cache, body.platform, body.profile, body.topic, body.style, body.duration, user_id)
            
            user_history: List[Dict[str, Any]] = []
            for m in body.history or []:
                user_history.append({"role": m.get("role", "user"), "parts": [m.get("content", "")]})

            # 使用用戶的 API Key 或系統預設的
            genai.configure(api_key=api_key)

            model_obj = genai.GenerativeModel(
                model_name=model_name,
                system_instruction=system_text
            )
            chat = model_obj.start_chat(history=user_history)

            async def generate():
                try:
                    stream_resp = chat.send_message(topics_prompt, stream=True)
                    for chunk in stream_resp:
                        if chunk.text:
                            yield f"data: {json.dumps({'type': 'token', 'content': chunk.text})}\n\n"
                    
                    if user_id:
                        save_conversation_summary(user_id, topics_prompt, "".join([c.text for c in stream_resp]))
                    
                    yield f"data: {json.dumps({'type': 'end'})}\n\n"
                except Exception as ex:
                    yield f"data: {json.dumps({'type': 'error', 'content': str(ex)})}\n\n"

            return StreamingResponse(generate(), media_type="text/plain")
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @app.post("/api/generate/script")
    @rate_limit("10/minute")
    async def generate_script(body: ChatBody, request: Request):
        """一鍵生成腳本"""
        # 檢查是否有用戶自定義的 API Key
        user_id = getattr(body, 'user_id', None)
        user_api_key = get_user_llm_key(user_id, "gemini") if user_id else None
        
        # 如果沒有用戶的 API Key，使用系統預設的
        api_key = user_api_key or os.getenv("GEMINI_API_KEY")
        
        if not api_key:
            return JSONResponse({"error": "Missing GEMINI_API_KEY in .env"}, status_code=500)

        # 專門的腳本生成提示詞
        script_prompt = f"""
你是AIJob短影音顧問，專門協助用戶生成短影音腳本。

基於以下信息生成完整腳本：
- 平台：{body.platform or '未設定'}
- 主題：{body.topic or '未設定'}
- 帳號定位：{body.profile or '未設定'}
- 時長：{body.duration or '30'}秒

請生成包含以下結構的完整腳本：
1. 主題標題
2. Hook（開場鉤子）
3. Value（核心價值內容）
4. CTA（行動呼籲）
5. 畫面感描述
6. 發佈文案

格式要求：分段清楚，短句，每段換行，適度加入表情符號，避免口頭禪。絕對不要使用 ** 或任何 Markdown 格式符號。
"""

        try:
            user_id = getattr(body, 'user_id', None)
            system_text = build_system_prompt(kb_text_cache, body.platform, body.profile, body.topic, body.style, body.duration, user_id)
            
            user_history: List[Dict[str, Any]] = []
            for m in body.history or []:
                user_history.append({"role": m.get("role", "user"), "parts": [m.get("content", "")]})

            # 使用用戶的 API Key 或系統預設的
            genai.configure(api_key=api_key)

            model_obj = genai.GenerativeModel(
                model_name=model_name,
                system_instruction=system_text
            )
            chat = model_obj.start_chat(history=user_history)

            async def generate():
                try:
                    stream_resp = chat.send_message(script_prompt, stream=True)
                    for chunk in stream_resp:
                        if chunk.text:
                            yield f"data: {json.dumps({'type': 'token', 'content': chunk.text})}\n\n"
                    
                    if user_id:
                        save_conversation_summary(user_id, script_prompt, "".join([c.text for c in stream_resp]))
                    
                    yield f"data: {json.dumps({'type': 'end'})}\n\n"
                except Exception as ex:
                    yield f"data: {json.dumps({'type': 'error', 'content': str(ex)})}\n\n"

            return StreamingResponse(generate(), media_type="text/plain")
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @app.post("/api/chat/stream")
    @rate_limit("30/minute")
    async def stream_chat(body: ChatBody, request: Request):
        user_id = getattr(body, 'user_id', None)
        
        # 檢查是否有用戶自定義的 API Key
        user_api_key = get_user_llm_key(user_id, "gemini") if user_id else None
        
        # 如果沒有用戶的 API Key，使用系統預設的
        api_key = user_api_key or os.getenv("GEMINI_API_KEY")
        
        if not api_key:
            return JSONResponse({"error": "Missing GEMINI_API_KEY in .env"}, status_code=500)
        
        # === 整合記憶系統 ===
        # 1. 載入短期記憶（STM）- 最近對話上下文
        stm_context = ""
        stm_history = []
        if user_id:
            stm_context = stm.get_context_for_prompt(user_id)
            stm_history = stm.get_recent_turns_for_history(user_id, limit=5)
        
        # 2. 載入長期記憶（LTM）- 您現有的系統
        ltm_memory = get_user_memory(user_id) if user_id else ""
        
        # 3. 組合增強版 prompt
        system_text = build_enhanced_prompt(
            kb_text=kb_text_cache,
            stm_context=stm_context,
            ltm_memory=ltm_memory,
            platform=body.platform,
            profile=body.profile,
            topic=body.topic,
            style=body.style,
            duration=body.duration
        )
        
        # 4. 合併前端傳來的 history 和 STM history
        user_history: List[Dict[str, Any]] = []
        
        # 優先使用 STM 的歷史（更完整）
        if stm_history:
            user_history = stm_history
        else:
            # 如果沒有 STM，使用前端傳來的 history
            for m in body.history or []:
                if m.role == "user":
                    user_history.append({"role": "user", "parts": [m.content]})
                elif m.role in ("assistant", "model"):
                    user_history.append({"role": "model", "parts": [m.content]})

        # 使用用戶的 API Key 或系統預設的
        genai.configure(api_key=api_key)

        model = genai.GenerativeModel(model_name)
        chat = model.start_chat(history=[
            {"role": "user", "parts": system_text},
            *user_history,
        ])

        def sse_events() -> Iterable[str]:
            yield f"data: {json.dumps({'type': 'start'})}\n\n"
            ai_response = ""
            try:
                stream = chat.send_message(body.message, stream=True)
                for chunk in stream:
                    try:
                        if chunk and getattr(chunk, "candidates", None):
                            parts = chunk.candidates[0].content.parts
                            if parts:
                                token = parts[0].text
                                if token:
                                    ai_response += token
                                    yield f"data: {json.dumps({'type': 'token', 'content': token})}\n\n"
                    except Exception:
                        continue
            except Exception as e:
                yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
            finally:
                # === 保存記憶 ===
                if user_id and ai_response:
                    # 1. 保存到短期記憶（STM）- 新增
                    stm.add_turn(
                        user_id=user_id,
                        user_message=body.message,
                        ai_response=ai_response,
                        metadata={
                            "platform": body.platform,
                            "topic": body.topic,
                            "profile": body.profile
                        }
                    )
                    
                    # 2. 保存到長期記憶（LTM）- 您原有的系統
                    save_conversation_summary(user_id, body.message, ai_response)
                
                yield f"data: {json.dumps({'type': 'end'})}\n\n"

        return StreamingResponse(sse_events(), media_type="text/event-stream")

    # ===== 長期記憶功能 API =====
    
    @app.get("/api/user/memory/{user_id}")
    async def get_user_memory_api(user_id: str, current_user_id: Optional[str] = Depends(get_current_user)):
        """獲取用戶的長期記憶資訊"""
        if not current_user_id or current_user_id != user_id:
            return JSONResponse({"error": "無權限訪問此用戶資料"}, status_code=403)
        try:
            memory = get_user_memory(user_id)
            return {"user_id": user_id, "memory": memory}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)
    
    @app.get("/api/user/conversations/{user_id}")
    async def get_user_conversations(user_id: str, current_user_id: Optional[str] = Depends(get_current_user)):
        """獲取用戶的對話記錄"""
        if not current_user_id or current_user_id != user_id:
            return JSONResponse({"error": "無權限訪問此用戶資料"}, status_code=403)
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            if use_postgresql:
                cursor.execute("""
                    SELECT id, conversation_type, summary, message_count, created_at FROM conversation_summaries 
                    WHERE user_id = %s 
                    ORDER BY created_at DESC 
                    LIMIT 100
                """, (user_id,))
            else:
                cursor.execute("""
                    SELECT id, conversation_type, summary, message_count, created_at FROM conversation_summaries 
                    WHERE user_id = ? 
                    ORDER BY created_at DESC 
                    LIMIT 100
                """, (user_id,))
            
            conversations = cursor.fetchall()
            
            conn.close()
            
            result = []
            for conv in conversations:
                conv_type_map = {
                    "account_positioning": "帳號定位",
                    "topic_selection": "選題討論",
                    "script_generation": "腳本生成",
                    "general_consultation": "AI顧問",
                    "ip_planning": "IP人設規劃"
                }
                result.append({
                    "id": conv[0],
                    "mode": conv_type_map.get(conv[1], conv[1]),
                    "summary": conv[2] or "",
                    "message_count": conv[3] or 0,
                    "created_at": conv[4]
                })
            
            return {
                "user_id": user_id,
                "conversations": result
            }
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    # ===== 用戶歷史API端點 =====
    
    @app.get("/api/user/generations/{user_id}")
    async def get_user_generations(user_id: str, current_user_id: Optional[str] = Depends(get_current_user)):
        """獲取用戶的生成記錄"""
        if not current_user_id or current_user_id != user_id:
            return JSONResponse({"error": "無權限訪問此用戶資料"}, status_code=403)
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            if use_postgresql:
                cursor.execute("""
                    SELECT platform, topic, content, created_at FROM generations 
                    WHERE user_id = %s 
                    ORDER BY created_at DESC 
                    LIMIT 10
                """, (user_id,))
            else:
                cursor.execute("""
                    SELECT platform, topic, content, created_at FROM generations 
                    WHERE user_id = ? 
                    ORDER BY created_at DESC 
                    LIMIT 10
                """, (user_id,))
            generations = cursor.fetchall()
            
            conn.close()
            
            return {
                "user_id": user_id,
                "generations": [
                    {
                        "platform": gen[0], 
                        "topic": gen[1], 
                        "content": gen[2][:100] + "..." if len(gen[2]) > 100 else gen[2],
                        "created_at": gen[3]
                    } 
                    for gen in generations
                ]
            }
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @app.get("/api/user/preferences/{user_id}")
    async def get_user_preferences(user_id: str, current_user_id: Optional[str] = Depends(get_current_user)):
        """獲取用戶的偏好設定"""
        if not current_user_id or current_user_id != user_id:
            return JSONResponse({"error": "無權限訪問此用戶資料"}, status_code=403)
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT preference_type, preference_value, confidence_score, updated_at 
                FROM user_preferences 
                WHERE user_id = ? 
                ORDER BY confidence_score DESC, updated_at DESC
            """, (user_id,))
            preferences = cursor.fetchall()
            
            conn.close()
            
            return {
                "user_id": user_id,
                "preferences": [
                    {
                        "type": pref[0],
                        "value": pref[1],
                        "confidence": pref[2],
                        "updated_at": pref[3]
                    } 
                    for pref in preferences
                ]
            }
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)
    
    # ===== 短期記憶（STM）API =====
    
    @app.get("/api/user/stm/{user_id}")
    async def get_user_stm(user_id: str, current_user_id: Optional[str] = Depends(get_current_user)):
        """獲取用戶的短期記憶（當前會話記憶）"""
        if not current_user_id or current_user_id != user_id:
            return JSONResponse({"error": "無權限訪問此用戶資料"}, status_code=403)
        try:
            memory = stm.load_memory(user_id)
            return {
                "user_id": user_id,
                "stm": {
                    "recent_turns": memory.get("recent_turns", []),
                    "last_summary": memory.get("last_summary", ""),
                    "turns_count": len(memory.get("recent_turns", [])),
                    "updated_at": memory.get("updated_at", 0)
                }
            }
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)
    
    @app.delete("/api/user/stm/{user_id}")
    async def clear_user_stm(user_id: str, current_user_id: Optional[str] = Depends(get_current_user)):
        """清除用戶的短期記憶"""
        if not current_user_id or current_user_id != user_id:
            return JSONResponse({"error": "無權限"}, status_code=403)
        try:
            stm.clear_memory(user_id)
            return {"message": "短期記憶已清除", "user_id": user_id}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)
    
    @app.get("/api/user/memory/full/{user_id}")
    async def get_full_memory(user_id: str, current_user_id: Optional[str] = Depends(get_current_user)):
        """獲取用戶的完整記憶（STM + LTM）"""
        if not current_user_id or current_user_id != user_id:
            return JSONResponse({"error": "無權限訪問此用戶資料"}, status_code=403)
        try:
            # STM
            stm_data = stm.load_memory(user_id)
            
            # LTM
            ltm_data = get_user_memory(user_id)
            
            # 格式化顯示
            memory_summary = format_memory_for_display({
                "stm": stm_data,
                "ltm": {"memory_text": ltm_data}
            })
            
            return {
                "user_id": user_id,
                "stm": {
                    "recent_turns_count": len(stm_data.get("recent_turns", [])),
                    "has_summary": bool(stm_data.get("last_summary")),
                    "updated_at": stm_data.get("updated_at", 0)
                },
                "ltm": {
                    "memory_text": ltm_data[:200] + "..." if len(ltm_data) > 200 else ltm_data
                },
                "summary": memory_summary
            }
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @app.post("/api/user/positioning/save")
    async def save_positioning_record(request: Request, current_user_id: Optional[str] = Depends(get_current_user)):
        """儲存帳號定位記錄"""
        try:
            data = await request.json()
            user_id = data.get("user_id")
            content = data.get("content")
            if not current_user_id or current_user_id != user_id:
                return JSONResponse({"error": "無權限儲存至此用戶"}, status_code=403)
            
            if not user_id or not content:
                return JSONResponse({"error": "缺少必要參數"}, status_code=400)
            
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            # 先檢查 user_profiles 是否存在該 user_id，若不存在則自動建立
            if use_postgresql:
                cursor.execute("SELECT user_id FROM user_profiles WHERE user_id = %s", (user_id,))
            else:
                cursor.execute("SELECT user_id FROM user_profiles WHERE user_id = ?", (user_id,))
            profile_exists = cursor.fetchone()
            
            if not profile_exists:
                # 自動建立 user_profiles 記錄
                if use_postgresql:
                    cursor.execute("""
                        INSERT INTO user_profiles (user_id, created_at)
                        VALUES (%s, CURRENT_TIMESTAMP)
                        ON CONFLICT (user_id) DO NOTHING
                    """, (user_id,))
                else:
                    cursor.execute("""
                        INSERT OR IGNORE INTO user_profiles (user_id, created_at)
                        VALUES (?, CURRENT_TIMESTAMP)
                    """, (user_id,))
                conn.commit()
            
            # 獲取該用戶的記錄數量來生成編號
            if use_postgresql:
                cursor.execute("SELECT COUNT(*) FROM positioning_records WHERE user_id = %s", (user_id,))
            else:
                cursor.execute("SELECT COUNT(*) FROM positioning_records WHERE user_id = ?", (user_id,))
            count = cursor.fetchone()[0]
            record_number = f"{count + 1:02d}"
            
            # 插入記錄
            if use_postgresql:
                cursor.execute("""
                    INSERT INTO positioning_records (user_id, record_number, content)
                    VALUES (%s, %s, %s)
                    RETURNING id
                """, (user_id, record_number, content))
                record_id = cursor.fetchone()[0]
            else:
                cursor.execute("""
                    INSERT INTO positioning_records (user_id, record_number, content)
                    VALUES (?, ?, ?)
                """, (user_id, record_number, content))
                conn.commit()
                record_id = cursor.lastrowid
            
            conn.close()
            
            return {
                "success": True,
                "record_id": record_id,
                "record_number": record_number
            }
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)
    
    @app.get("/api/user/positioning/{user_id}")
    async def get_positioning_records(user_id: str):
        """獲取用戶的所有帳號定位記錄"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            if use_postgresql:
                cursor.execute("""
                    SELECT id, record_number, content, created_at
                    FROM positioning_records
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                """, (user_id,))
            else:
                cursor.execute("""
                    SELECT id, record_number, content, created_at
                    FROM positioning_records
                    WHERE user_id = ?
                    ORDER BY created_at DESC
                """, (user_id,))
            
            records = []
            for row in cursor.fetchall():
                records.append({
                    "id": row[0],
                    "record_number": row[1],
                    "content": row[2],
                    "created_at": row[3]
                })
            
            conn.close()
            return {"records": records}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)
    
    @app.delete("/api/user/positioning/{record_id}")
    async def delete_positioning_record(record_id: int, current_user_id: Optional[str] = Depends(get_current_user)):
        """刪除帳號定位記錄"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            # 檢查擁有者
            if use_postgresql:
                cursor.execute("SELECT user_id FROM positioning_records WHERE id = %s", (record_id,))
            else:
                cursor.execute("SELECT user_id FROM positioning_records WHERE id = ?", (record_id,))
            row = cursor.fetchone()
            if not row:
                conn.close()
                return JSONResponse({"error": "記錄不存在"}, status_code=404)
            if not current_user_id or row[0] != current_user_id:
                conn.close()
                return JSONResponse({"error": "無權限刪除此記錄"}, status_code=403)
            
            if use_postgresql:
                cursor.execute("DELETE FROM positioning_records WHERE id = %s", (record_id,))
            else:
                cursor.execute("DELETE FROM positioning_records WHERE id = ?", (record_id,))
            
            if not use_postgresql:
                conn.commit()
            conn.close()
            
            return {"success": True}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    # ===== 腳本儲存功能 API =====
    
    @app.post("/api/scripts/save")
    async def save_script(request: Request, current_user_id: Optional[str] = Depends(get_current_user)):
        """儲存腳本"""
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                data = await request.json()
                user_id = data.get("user_id")
                content = data.get("content")
                script_data = data.get("script_data", {})
                platform = data.get("platform")
                topic = data.get("topic")
                profile = data.get("profile")
                
                if not user_id or not content:
                    return JSONResponse({"error": "缺少必要參數"}, status_code=400)
                if not current_user_id or current_user_id != user_id:
                    return JSONResponse({"error": "無權限儲存至此用戶"}, status_code=403)
                
                conn = get_db_connection()
                cursor = conn.cursor()
                
                database_url = os.getenv("DATABASE_URL")
                use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
                
                # 提取腳本標題作為預設名稱
                script_name = script_data.get("title", "未命名腳本")
                
                # 插入腳本記錄
                if use_postgresql:
                    cursor.execute("""
                        INSERT INTO user_scripts (user_id, script_name, title, content, script_data, platform, topic, profile)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING id
                    """, (
                        user_id,
                        script_name,
                        script_data.get("title", ""),
                        content,
                        json.dumps(script_data),
                        platform,
                        topic,
                        profile
                    ))
                    script_id = cursor.fetchone()[0]
                else:
                    cursor.execute("""
                        INSERT INTO user_scripts (user_id, script_name, title, content, script_data, platform, topic, profile)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        user_id,
                        script_name,
                        script_data.get("title", ""),
                        content,
                        json.dumps(script_data),
                        platform,
                        topic,
                        profile
                    ))
                    conn.commit()
                    script_id = cursor.lastrowid
                
                conn.close()
                
                return {
                    "success": True,
                    "script_id": script_id,
                    "message": "腳本儲存成功"
                }
            except sqlite3.OperationalError as e:
                if "database is locked" in str(e) and retry_count < max_retries - 1:
                    retry_count += 1
                    await asyncio.sleep(0.1 * retry_count)  # 遞增延遲
                    continue
                else:
                    return JSONResponse({"error": f"資料庫錯誤: {str(e)}"}, status_code=500)
            except Exception as e:
                return JSONResponse({"error": f"儲存失敗: {str(e)}"}, status_code=500)
        
        return JSONResponse({"error": "儲存失敗，請稍後再試"}, status_code=500)
    
    @app.post("/api/ip-planning/save")
    async def save_ip_planning_result(request: Request, current_user_id: Optional[str] = Depends(get_current_user)):
        """儲存 IP 人設規劃結果（IP Profile、14天規劃、今日腳本）"""
        try:
            data = await request.json()
            user_id = data.get("user_id")
            result_type = data.get("result_type")  # 'profile', 'plan', 'scripts'
            title = data.get("title", "")
            content = data.get("content")
            metadata = data.get("metadata", {})
            
            if not current_user_id or current_user_id != user_id:
                return JSONResponse({"error": "無權限儲存至此用戶"}, status_code=403)
            
            if not user_id or not result_type or not content:
                return JSONResponse({"error": "缺少必要參數"}, status_code=400)
            
            if result_type not in ['profile', 'plan', 'scripts']:
                return JSONResponse({"error": "無效的結果類型"}, status_code=400)
            
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            # 確保 user_profiles 存在該 user_id
            if use_postgresql:
                cursor.execute("SELECT user_id FROM user_profiles WHERE user_id = %s", (user_id,))
            else:
                cursor.execute("SELECT user_id FROM user_profiles WHERE user_id = ?", (user_id,))
            profile_exists = cursor.fetchone()
            
            if not profile_exists:
                if use_postgresql:
                    cursor.execute("""
                        INSERT INTO user_profiles (user_id, created_at)
                        VALUES (%s, CURRENT_TIMESTAMP)
                        ON CONFLICT (user_id) DO NOTHING
                    """, (user_id,))
                else:
                    cursor.execute("""
                        INSERT OR IGNORE INTO user_profiles (user_id, created_at)
                        VALUES (?, CURRENT_TIMESTAMP)
                    """, (user_id,))
                conn.commit()
            
            # 插入結果記錄
            if use_postgresql:
                cursor.execute("""
                    INSERT INTO ip_planning_results (user_id, result_type, title, content, metadata)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id
                """, (
                    user_id,
                    result_type,
                    title,
                    content,
                    json.dumps(metadata)
                ))
                result_id = cursor.fetchone()[0]
            else:
                cursor.execute("""
                    INSERT INTO ip_planning_results (user_id, result_type, title, content, metadata)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    user_id,
                    result_type,
                    title,
                    content,
                    json.dumps(metadata)
                ))
                conn.commit()
                result_id = cursor.lastrowid
            
            conn.close()
            
            return {
                "success": True,
                "result_id": result_id,
                "message": "結果儲存成功"
            }
        except Exception as e:
            return JSONResponse({"error": f"儲存失敗: {str(e)}"}, status_code=500)
    
    @app.get("/api/ip-planning/my")
    async def get_my_ip_planning_results(current_user_id: Optional[str] = Depends(get_current_user), result_type: Optional[str] = None):
        """獲取用戶的 IP 人設規劃結果列表"""
        if not current_user_id:
            return JSONResponse({"error": "請先登入"}, status_code=401)
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            if result_type:
                # 獲取特定類型的結果
                if use_postgresql:
                    cursor.execute("""
                        SELECT id, result_type, title, content, metadata, created_at, updated_at
                        FROM ip_planning_results
                        WHERE user_id = %s AND result_type = %s
                        ORDER BY created_at DESC
                    """, (current_user_id, result_type))
                else:
                    cursor.execute("""
                        SELECT id, result_type, title, content, metadata, created_at, updated_at
                        FROM ip_planning_results
                        WHERE user_id = ? AND result_type = ?
                        ORDER BY created_at DESC
                    """, (current_user_id, result_type))
            else:
                # 獲取所有結果
                if use_postgresql:
                    cursor.execute("""
                        SELECT id, result_type, title, content, metadata, created_at, updated_at
                        FROM ip_planning_results
                        WHERE user_id = %s
                        ORDER BY created_at DESC
                    """, (current_user_id,))
                else:
                    cursor.execute("""
                        SELECT id, result_type, title, content, metadata, created_at, updated_at
                        FROM ip_planning_results
                        WHERE user_id = ?
                        ORDER BY created_at DESC
                    """, (current_user_id,))
            
            results = cursor.fetchall()
            conn.close()
            
            # 格式化結果
            formatted_results = []
            for row in results:
                formatted_results.append({
                    "id": row[0],
                    "result_type": row[1],
                    "title": row[2] or "",
                    "content": row[3],
                    "metadata": json.loads(row[4]) if row[4] else {},
                    "created_at": row[5].isoformat() if row[5] else None,
                    "updated_at": row[6].isoformat() if row[6] else None
                })
            
            return {"success": True, "results": formatted_results}
        except Exception as e:
            return JSONResponse({"error": f"獲取失敗: {str(e)}"}, status_code=500)
    
    @app.get("/api/scripts/my")
    async def get_my_scripts(current_user_id: Optional[str] = Depends(get_current_user)):
        """獲取用戶的腳本列表"""
        if not current_user_id:
            return JSONResponse({"error": "請先登入"}, status_code=401)
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            if use_postgresql:
                cursor.execute("""
                    SELECT id, script_name, title, content, script_data, platform, topic, profile, created_at, updated_at
                    FROM user_scripts
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                """, (current_user_id,))
            else:
                cursor.execute("""
                    SELECT id, script_name, title, content, script_data, platform, topic, profile, created_at, updated_at
                    FROM user_scripts
                    WHERE user_id = ?
                    ORDER BY created_at DESC
                """, (current_user_id,))
            
            scripts = []
            for row in cursor.fetchall():
                script_data = json.loads(row[4]) if row[4] else {}
                scripts.append({
                    "id": row[0],
                    "name": row[1],
                    "title": row[2],
                    "content": row[3],
                    "script_data": script_data,
                    "platform": row[5],
                    "topic": row[6],
                    "profile": row[7],
                    "created_at": row[8],
                    "updated_at": row[9]
                })
            
            conn.close()
            return {"scripts": scripts}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)
    
    # 長期記憶相關API
    @app.post("/api/memory/long-term")
    async def save_long_term_memory(
        request_body: LongTermMemoryRequest,
        current_user_id: Optional[str] = Depends(get_current_user)
    ):
        """儲存長期記憶對話"""
        print(f"DEBUG: save_long_term_memory - 收到請求，current_user_id={current_user_id}")
        print(f"DEBUG: request_body.conversation_type={request_body.conversation_type}")
        print(f"DEBUG: request_body.session_id={request_body.session_id}")
        print(f"DEBUG: request_body.message_role={request_body.message_role}")
        print(f"DEBUG: request_body.message_content 長度={len(request_body.message_content) if request_body.message_content else 0}")
        
        if not current_user_id:
            print(f"ERROR: save_long_term_memory - current_user_id 為空，返回 401")
            return JSONResponse({"error": "請先登入"}, status_code=401)
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            if use_postgresql:
                cursor.execute("""
                    INSERT INTO long_term_memory (user_id, conversation_type, session_id, message_role, message_content, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (current_user_id, request_body.conversation_type, request_body.session_id, request_body.message_role, request_body.message_content, request_body.metadata))
                print(f"DEBUG: save_long_term_memory - PostgreSQL INSERT 成功，user_id={current_user_id}")
            else:
                cursor.execute("""
                    INSERT INTO long_term_memory (user_id, conversation_type, session_id, message_role, message_content, metadata)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (current_user_id, request_body.conversation_type, request_body.session_id, request_body.message_role, request_body.message_content, request_body.metadata))
                print(f"DEBUG: save_long_term_memory - SQLite INSERT 成功，user_id={current_user_id}")
            
            if not use_postgresql:
                conn.commit()
            conn.close()
            print(f"SUCCESS: save_long_term_memory - 長期記憶已儲存，user_id={current_user_id}, conversation_type={request_body.conversation_type}")
            return {"success": True, "message": "長期記憶已儲存"}
        except Exception as e:
            print(f"ERROR: save_long_term_memory - 發生異常: {str(e)}")
            import traceback
            traceback.print_exc()
            return JSONResponse({"error": str(e)}, status_code=500)
    
    @app.get("/api/memory/long-term")
    async def get_long_term_memory(
        conversation_type: Optional[str] = None,
        session_id: Optional[str] = None,
        limit: int = 50,
        current_user_id: Optional[str] = Depends(get_current_user)
    ):
        """獲取長期記憶對話"""
        if not current_user_id:
            return JSONResponse({"error": "請先登入"}, status_code=401)
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            if use_postgresql:
                if conversation_type and session_id:
                    cursor.execute("""
                        SELECT id, conversation_type, session_id, message_role, message_content, metadata, created_at
                        FROM long_term_memory
                        WHERE user_id = %s AND conversation_type = %s AND session_id = %s
                        ORDER BY created_at DESC
                        LIMIT %s
                    """, (current_user_id, conversation_type, session_id, limit))
                elif conversation_type:
                    cursor.execute("""
                        SELECT id, conversation_type, session_id, message_role, message_content, metadata, created_at
                        FROM long_term_memory
                        WHERE user_id = %s AND conversation_type = %s
                        ORDER BY created_at DESC
                        LIMIT %s
                    """, (current_user_id, conversation_type, limit))
                else:
                    cursor.execute("""
                        SELECT id, conversation_type, session_id, message_role, message_content, metadata, created_at
                        FROM long_term_memory
                        WHERE user_id = %s
                        ORDER BY created_at DESC
                        LIMIT %s
                    """, (current_user_id, limit))
            else:
                if conversation_type and session_id:
                    cursor.execute("""
                        SELECT id, conversation_type, session_id, message_role, message_content, metadata, created_at
                        FROM long_term_memory
                        WHERE user_id = ? AND conversation_type = ? AND session_id = ?
                        ORDER BY created_at DESC
                        LIMIT ?
                    """, (current_user_id, conversation_type, session_id, limit))
                elif conversation_type:
                    cursor.execute("""
                        SELECT id, conversation_type, session_id, message_role, message_content, metadata, created_at
                        FROM long_term_memory
                        WHERE user_id = ? AND conversation_type = ?
                        ORDER BY created_at DESC
                        LIMIT ?
                    """, (current_user_id, conversation_type, limit))
                else:
                    cursor.execute("""
                        SELECT id, conversation_type, session_id, message_role, message_content, metadata, created_at
                        FROM long_term_memory
                        WHERE user_id = ?
                        ORDER BY created_at DESC
                        LIMIT ?
                    """, (current_user_id, limit))
            
            memories = []
            for row in cursor.fetchall():
                memories.append({
                    "id": row[0],
                    "conversation_type": row[1],
                    "session_id": row[2],
                    "message_role": row[3],
                    "message_content": row[4],
                    "metadata": row[5],
                    "created_at": row[6]
                })
            
            conn.close()
            return {"memories": memories}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)
    
    # 管理員長期記憶API
    @app.get("/api/admin/long-term-memory")
    async def get_all_long_term_memory(conversation_type: Optional[str] = None, limit: int = 1000, admin_user: str = Depends(get_admin_user)):
        """獲取所有長期記憶記錄（管理員用）"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            if use_postgresql:
                if conversation_type:
                    cursor.execute("""
                        SELECT ltm.id, ltm.user_id, ltm.conversation_type, ltm.session_id, 
                               ltm.message_role, ltm.message_content, ltm.metadata, ltm.created_at,
                               ua.name, ua.email
                        FROM long_term_memory ltm
                        LEFT JOIN user_auth ua ON ltm.user_id = ua.user_id
                        WHERE ltm.conversation_type = %s
                        ORDER BY ltm.created_at DESC
                        LIMIT %s
                    """, (conversation_type, limit))
                else:
                    cursor.execute("""
                        SELECT ltm.id, ltm.user_id, ltm.conversation_type, ltm.session_id, 
                               ltm.message_role, ltm.message_content, ltm.metadata, ltm.created_at,
                               ua.name, ua.email
                        FROM long_term_memory ltm
                        LEFT JOIN user_auth ua ON ltm.user_id = ua.user_id
                        ORDER BY ltm.created_at DESC
                        LIMIT %s
                    """, (limit,))
            else:
                if conversation_type:
                    cursor.execute("""
                        SELECT ltm.id, ltm.user_id, ltm.conversation_type, ltm.session_id, 
                               ltm.message_role, ltm.message_content, ltm.metadata, ltm.created_at,
                               ua.name, ua.email
                        FROM long_term_memory ltm
                        LEFT JOIN user_auth ua ON ltm.user_id = ua.user_id
                        WHERE ltm.conversation_type = ?
                        ORDER BY ltm.created_at DESC
                        LIMIT ?
                    """, (conversation_type, limit))
                else:
                    cursor.execute("""
                        SELECT ltm.id, ltm.user_id, ltm.conversation_type, ltm.session_id, 
                               ltm.message_role, ltm.message_content, ltm.metadata, ltm.created_at,
                               ua.name, ua.email
                        FROM long_term_memory ltm
                        LEFT JOIN user_auth ua ON ltm.user_id = ua.user_id
                        ORDER BY ltm.created_at DESC
                        LIMIT ?
                    """, (limit,))
            
            memories = []
            for row in cursor.fetchall():
                memories.append({
                    "id": row[0],
                    "user_id": row[1],
                    "conversation_type": row[2],
                    "session_id": row[3],
                    "message_role": row[4],
                    "message_content": row[5],
                    "metadata": row[6],
                    "created_at": row[7],
                    "user_name": row[8],
                    "user_email": row[9]
                })
            
            conn.close()
            return {"memories": memories}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    # 取得單筆長期記憶（管理員用）
    @app.get("/api/admin/long-term-memory/by-user")
    async def get_long_term_memory_by_user(admin_user: str = Depends(get_admin_user)):
        """按用戶分組獲取長期記憶統計（管理員用）"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            if use_postgresql:
                cursor.execute("""
                    SELECT 
                        ltm.user_id,
                        COALESCE(ua.name, '未知') as name,
                        COALESCE(ua.email, '未知') as email,
                        COUNT(*) as total_memories,
                        COUNT(DISTINCT ltm.conversation_type) as conversation_types,
                        COUNT(DISTINCT ltm.session_id) as session_count,
                        MIN(ltm.created_at) as first_memory,
                        MAX(ltm.created_at) as last_memory,
                        STRING_AGG(DISTINCT ltm.conversation_type, ', ') as types_list
                    FROM long_term_memory ltm
                    LEFT JOIN user_auth ua ON ltm.user_id = ua.user_id
                    GROUP BY ltm.user_id, ua.name, ua.email
                    ORDER BY total_memories DESC
                """)
            else:
                cursor.execute("""
                    SELECT 
                        ltm.user_id,
                        COALESCE(ua.name, '未知') as name,
                        COALESCE(ua.email, '未知') as email,
                        COUNT(*) as total_memories,
                        COUNT(DISTINCT ltm.conversation_type) as conversation_types,
                        COUNT(DISTINCT ltm.session_id) as session_count,
                        MIN(ltm.created_at) as first_memory,
                        MAX(ltm.created_at) as last_memory,
                        GROUP_CONCAT(DISTINCT ltm.conversation_type) as types_list
                    FROM long_term_memory ltm
                    LEFT JOIN user_auth ua ON ltm.user_id = ua.user_id
                    GROUP BY ltm.user_id, ua.name, ua.email
                    ORDER BY total_memories DESC
                """)
            
            users = []
            rows = cursor.fetchall()
            
            # 調試：記錄查詢結果數量
            print(f"DEBUG: long-term-memory/by-user 查詢返回 {len(rows)} 筆記錄")
            print(f"DEBUG: 查詢的 SQL: {cursor.query if hasattr(cursor, 'query') else 'N/A'}")
            
            # 調試：先檢查 long_term_memory 表中有多少記錄
            if use_postgresql:
                cursor.execute("SELECT COUNT(*) FROM long_term_memory")
            else:
                cursor.execute("SELECT COUNT(*) FROM long_term_memory")
            total_memories = cursor.fetchone()[0]
            print(f"DEBUG: long_term_memory 表總共有 {total_memories} 筆記錄")
            
            # 調試：檢查有多少不同的 user_id
            if use_postgresql:
                cursor.execute("SELECT COUNT(DISTINCT user_id) FROM long_term_memory")
            else:
                cursor.execute("SELECT COUNT(DISTINCT user_id) FROM long_term_memory")
            distinct_users = cursor.fetchone()[0]
            print(f"DEBUG: long_term_memory 表中有 {distinct_users} 個不同的用戶")
            
            # 調試：列出所有 user_id
            if use_postgresql:
                cursor.execute("SELECT DISTINCT user_id FROM long_term_memory LIMIT 10")
            else:
                cursor.execute("SELECT DISTINCT user_id FROM long_term_memory LIMIT 10")
            user_ids = cursor.fetchall()
            print(f"DEBUG: 前10個 user_id: {[row[0] for row in user_ids]}")
            
            for row in rows:
                users.append({
                    "user_id": row[0] or "",
                    "user_name": row[1] or "未知",
                    "user_email": row[2] or "",
                    "total_memories": row[3] or 0,
                    "conversation_types": row[4] or 0,
                    "session_count": row[5] or 0,
                    "first_memory": row[6] or "",
                    "last_memory": row[7] or "",
                    "types_list": row[8] if row[8] else ""
                })
            
            conn.close()
            
            # 調試：記錄返回的數據
            print(f"DEBUG: long-term-memory/by-user 返回 {len(users)} 個用戶")
            for user in users:
                print(f"DEBUG: 用戶 - ID: {user['user_id']}, 名稱: {user['user_name']}, Email: {user['user_email']}, 記憶數: {user['total_memories']}")
            
            return {"users": users}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)
    
    @app.get("/api/admin/long-term-memory/{memory_id}")
    async def get_long_term_memory_by_id(memory_id: int, admin_user: str = Depends(get_admin_user)):
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE

            if use_postgresql:
                cursor.execute(
                    """
                    SELECT ltm.id, ltm.user_id, ltm.conversation_type, ltm.session_id,
                           ltm.message_role, ltm.message_content, ltm.metadata, ltm.created_at,
                           ua.name, ua.email
                    FROM long_term_memory ltm
                    LEFT JOIN user_auth ua ON ltm.user_id = ua.user_id
                    WHERE ltm.id = %s
                    """,
                    (memory_id,)
                )
            else:
                cursor.execute(
                    """
                    SELECT ltm.id, ltm.user_id, ltm.conversation_type, ltm.session_id,
                           ltm.message_role, ltm.message_content, ltm.metadata, ltm.created_at,
                           ua.name, ua.email
                    FROM long_term_memory ltm
                    LEFT JOIN user_auth ua ON ltm.user_id = ua.user_id
                    WHERE ltm.id = ?
                    """,
                    (memory_id,)
                )

            row = cursor.fetchone()
            conn.close()
            if not row:
                return JSONResponse({"error": "記錄不存在"}, status_code=404)

            return {
                "id": row[0],
                "user_id": row[1],
                "conversation_type": row[2],
                "session_id": row[3],
                "message_role": row[4],
                "message_content": row[5],
                "metadata": row[6],
                "created_at": row[7],
                "user_name": row[8],
                "user_email": row[9]
            }
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    # 刪除單筆長期記憶（管理員用）
    @app.delete("/api/admin/long-term-memory/{memory_id}")
    async def delete_long_term_memory(memory_id: int, admin_user: str = Depends(get_admin_user)):
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE

            # 檢查存在
            if use_postgresql:
                cursor.execute("SELECT id FROM long_term_memory WHERE id = %s", (memory_id,))
            else:
                cursor.execute("SELECT id FROM long_term_memory WHERE id = ?", (memory_id,))
            if not cursor.fetchone():
                conn.close()
                return JSONResponse({"error": "記錄不存在"}, status_code=404)

            # 刪除
            if use_postgresql:
                cursor.execute("DELETE FROM long_term_memory WHERE id = %s", (memory_id,))
            else:
                cursor.execute("DELETE FROM long_term_memory WHERE id = ?", (memory_id,))
                conn.commit()

            conn.close()
            return {"success": True}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)
    
    @app.get("/api/admin/long-term-memory/user/{user_id}")
    async def get_user_long_term_memory_admin(user_id: str, admin_user: str = Depends(get_admin_user)):
        """獲取指定用戶的所有長期記憶（管理員用）"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            if use_postgresql:
                cursor.execute("""
                    SELECT 
                        ltm.id, ltm.conversation_type, ltm.session_id, 
                        ltm.message_role, ltm.message_content, ltm.metadata, ltm.created_at,
                        COALESCE(ua.name, '未知') as name,
                        COALESCE(ua.email, '未知') as email
                    FROM long_term_memory ltm
                    LEFT JOIN user_auth ua ON ltm.user_id = ua.user_id
                    WHERE ltm.user_id = %s
                    ORDER BY ltm.created_at DESC
                    LIMIT 1000
                """, (user_id,))
            else:
                cursor.execute("""
                    SELECT 
                        ltm.id, ltm.conversation_type, ltm.session_id, 
                        ltm.message_role, ltm.message_content, ltm.metadata, ltm.created_at,
                        COALESCE(ua.name, '未知') as name,
                        COALESCE(ua.email, '未知') as email
                    FROM long_term_memory ltm
                    LEFT JOIN user_auth ua ON ltm.user_id = ua.user_id
                    WHERE ltm.user_id = ?
                    ORDER BY ltm.created_at DESC
                    LIMIT 1000
                """, (user_id,))
            
            memories = []
            for row in cursor.fetchall():
                memories.append({
                    "id": row[0],
                    "conversation_type": row[1],
                    "session_id": row[2],
                    "message_role": row[3],
                    "message_content": row[4],
                    "metadata": row[5],
                    "created_at": row[6],
                    "user_name": row[7],
                    "user_email": row[8]
                })
            
            conn.close()
            return {"memories": memories, "user_id": user_id}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)
    
    @app.get("/api/admin/memory-stats")
    async def get_memory_stats(admin_user: str = Depends(get_admin_user)):
        """獲取長期記憶統計（管理員用）"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            if use_postgresql:
                # 總記憶數
                cursor.execute("SELECT COUNT(*) FROM long_term_memory")
                total_memories = cursor.fetchone()[0]
                
                # 活躍用戶數
                cursor.execute("SELECT COUNT(DISTINCT user_id) FROM long_term_memory")
                active_users = cursor.fetchone()[0]
                
                # 今日新增記憶數
                cursor.execute("""
                    SELECT COUNT(*) FROM long_term_memory 
                    WHERE DATE(created_at) = CURRENT_DATE
                """)
                today_memories = cursor.fetchone()[0]
                
                # 平均記憶/用戶
                avg_memories_per_user = total_memories / active_users if active_users > 0 else 0
                
            else:
                # SQLite 版本
                cursor.execute("SELECT COUNT(*) FROM long_term_memory")
                total_memories = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(DISTINCT user_id) FROM long_term_memory")
                active_users = cursor.fetchone()[0]
                
                cursor.execute("""
                    SELECT COUNT(*) FROM long_term_memory 
                    WHERE DATE(created_at) = DATE('now')
                """)
                today_memories = cursor.fetchone()[0]
                
                avg_memories_per_user = total_memories / active_users if active_users > 0 else 0
            
            conn.close()
            return {
                "total_memories": total_memories,
                "active_users": active_users,
                "today_memories": today_memories,
                "avg_memories_per_user": round(avg_memories_per_user, 2)
            }
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)
    
    # 獲取用戶的長期記憶（支援會話篩選）
    @app.get("/api/memory/long-term")
    async def get_user_long_term_memory(
        conversation_type: Optional[str] = None,
        session_id: Optional[str] = None,
        limit: int = 50,
        current_user_id: Optional[str] = Depends(get_current_user)
    ):
        """獲取用戶的長期記憶記錄"""
        if not current_user_id:
            return JSONResponse({"error": "請先登入"}, status_code=401)
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            # 構建查詢條件
            where_conditions = ["user_id = ?" if not use_postgresql else "user_id = %s"]
            params = [current_user_id]
            
            if conversation_type:
                where_conditions.append("conversation_type = ?" if not use_postgresql else "conversation_type = %s")
                params.append(conversation_type)
            
            if session_id:
                where_conditions.append("session_id = ?" if not use_postgresql else "session_id = %s")
                params.append(session_id)
            
            where_clause = " AND ".join(where_conditions)
            
            if use_postgresql:
                cursor.execute(f"""
                    SELECT id, user_id, conversation_type, session_id, 
                           message_role, message_content, metadata, created_at
                    FROM long_term_memory
                    WHERE {where_clause}
                    ORDER BY created_at ASC
                    LIMIT %s
                """, params + [limit])
            else:
                cursor.execute(f"""
                    SELECT id, user_id, conversation_type, session_id, 
                           message_role, message_content, metadata, created_at
                    FROM long_term_memory
                    WHERE {where_clause}
                    ORDER BY created_at ASC
                    LIMIT ?
                """, params + [limit])
            
            memories = []
            for row in cursor.fetchall():
                memories.append({
                    "id": row[0],
                    "user_id": row[1],
                    "conversation_type": row[2],
                    "session_id": row[3],
                    "message_role": row[4],
                    "message_content": row[5],
                    "metadata": row[6],
                    "created_at": row[7]
                })
            
            conn.close()
            return {"memories": memories}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)
    
    # 獲取用戶的會話列表
    @app.get("/api/memory/sessions")
    async def get_user_sessions(
        conversation_type: Optional[str] = None,
        limit: int = 20,
        current_user_id: Optional[str] = Depends(get_current_user)
    ):
        """獲取用戶的會話列表"""
        if not current_user_id:
            return JSONResponse({"error": "請先登入"}, status_code=401)
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            where_condition = "user_id = ?" if not use_postgresql else "user_id = %s"
            params = [current_user_id]
            
            if conversation_type:
                where_condition += " AND conversation_type = ?" if not use_postgresql else " AND conversation_type = %s"
                params.append(conversation_type)
            
            if use_postgresql:
                cursor.execute(f"""
                    SELECT session_id, 
                           MAX(created_at) as last_time,
                           COUNT(*) as message_count,
                           MAX(CASE WHEN message_role = 'user' THEN message_content END) as last_user_message,
                           MAX(CASE WHEN message_role = 'assistant' THEN message_content END) as last_ai_message
                    FROM long_term_memory
                    WHERE {where_condition}
                    GROUP BY session_id
                    ORDER BY last_time DESC
                    LIMIT %s
                """, params + [limit])
            else:
                cursor.execute(f"""
                    SELECT session_id, 
                           MAX(created_at) as last_time,
                           COUNT(*) as message_count,
                           MAX(CASE WHEN message_role = 'user' THEN message_content END) as last_user_message,
                           MAX(CASE WHEN message_role = 'assistant' THEN message_content END) as last_ai_message
                    FROM long_term_memory
                    WHERE {where_condition}
                    GROUP BY session_id
                    ORDER BY last_time DESC
                    LIMIT ?
                """, params + [limit])
            
            sessions = []
            for row in cursor.fetchall():
                sessions.append({
                    "session_id": row[0],
                    "last_time": row[1],
                    "message_count": row[2],
                    "last_user_message": row[3],
                    "last_ai_message": row[4]
                })
            
            conn.close()
            return {"sessions": sessions}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)
    
    @app.put("/api/scripts/{script_id}/name")
    async def update_script_name(script_id: int, request: Request, current_user_id: Optional[str] = Depends(get_current_user)):
        """更新腳本名稱"""
        if not current_user_id:
            return JSONResponse({"error": "請先登入"}, status_code=401)
        
        try:
            data = await request.json()
            new_name = data.get("name")
            
            if not new_name:
                return JSONResponse({"error": "腳本名稱不能為空"}, status_code=400)
            
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            # 檢查腳本是否屬於當前用戶
            if use_postgresql:
                cursor.execute("SELECT user_id FROM user_scripts WHERE id = %s", (script_id,))
            else:
                cursor.execute("SELECT user_id FROM user_scripts WHERE id = ?", (script_id,))
            result = cursor.fetchone()
            
            if not result:
                return JSONResponse({"error": "腳本不存在"}, status_code=404)
            
            if result[0] != current_user_id:
                return JSONResponse({"error": "無權限修改此腳本"}, status_code=403)
            
            # 更新腳本名稱
            if use_postgresql:
                cursor.execute("""
                    UPDATE user_scripts 
                    SET script_name = %s, updated_at = CURRENT_TIMESTAMP
                    WHERE id = %s
                """, (new_name, script_id))
            else:
                cursor.execute("""
                    UPDATE user_scripts 
                    SET script_name = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (new_name, script_id))
            
            if not use_postgresql:
                conn.commit()
            conn.close()
            
            return {"success": True, "message": "腳本名稱更新成功"}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)
    
    @app.delete("/api/scripts/{script_id}")
    async def delete_script(script_id: int, current_user_id: Optional[str] = Depends(get_current_user)):
        """刪除腳本"""
        if not current_user_id:
            return JSONResponse({"error": "請先登入"}, status_code=401)
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            # 檢查腳本是否屬於當前用戶
            if use_postgresql:
                cursor.execute("SELECT user_id FROM user_scripts WHERE id = %s", (script_id,))
            else:
                cursor.execute("SELECT user_id FROM user_scripts WHERE id = ?", (script_id,))
            result = cursor.fetchone()
            
            if not result:
                return JSONResponse({"error": "腳本不存在"}, status_code=404)
            
            if result[0] != current_user_id:
                return JSONResponse({"error": "無權限刪除此腳本"}, status_code=403)
            
            # 刪除腳本
            if use_postgresql:
                cursor.execute("DELETE FROM user_scripts WHERE id = %s", (script_id,))
            else:
                cursor.execute("DELETE FROM user_scripts WHERE id = ?", (script_id,))
            
            if not use_postgresql:
                conn.commit()
            conn.close()
            
            return {"success": True, "message": "腳本刪除成功"}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @app.get("/api/user/behaviors/{user_id}")
    async def get_user_behaviors(user_id: str, current_user_id: Optional[str] = Depends(get_current_user)):
        """獲取用戶的行為統計"""
        if not current_user_id or current_user_id != user_id:
            return JSONResponse({"error": "無權限訪問此用戶資料"}, status_code=403)
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            if use_postgresql:
                cursor.execute("""
                    SELECT behavior_type, COUNT(*) as count, MAX(created_at) as last_activity
                    FROM user_behaviors 
                    WHERE user_id = %s 
                    GROUP BY behavior_type
                    ORDER BY count DESC
                """, (user_id,))
            else:
                cursor.execute("""
                    SELECT behavior_type, COUNT(*) as count, MAX(created_at) as last_activity
                    FROM user_behaviors 
                    WHERE user_id = ? 
                    GROUP BY behavior_type
                    ORDER BY count DESC
                """, (user_id,))
            behaviors = cursor.fetchall()
            
            conn.close()
            
            return {
                "user_id": user_id,
                "behaviors": [
                    {
                        "type": behavior[0],
                        "count": behavior[1],
                        "last_activity": behavior[2]
                    } 
                    for behavior in behaviors
                ]
            }
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    # ===== 管理員 API（用於後台管理系統） =====
    
    @app.get("/api/admin/users")
    async def get_all_users(admin_user: str = Depends(get_admin_user)):
        """獲取所有用戶資料（管理員用）"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # 獲取所有用戶基本資料（包含訂閱狀態和統計）
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            if use_postgresql:
                cursor.execute("""
                    SELECT ua.user_id, ua.google_id, ua.email, ua.name, ua.picture, 
                           ua.created_at, ua.is_subscribed, up.preferred_platform, up.preferred_style, up.preferred_duration
                    FROM user_auth ua
                    LEFT JOIN user_profiles up ON ua.user_id = up.user_id
                    ORDER BY ua.created_at DESC
                """)
            else:
                cursor.execute("""
                    SELECT ua.user_id, ua.google_id, ua.email, ua.name, ua.picture, 
                           ua.created_at, ua.is_subscribed, up.preferred_platform, up.preferred_style, up.preferred_duration
                    FROM user_auth ua
                    LEFT JOIN user_profiles up ON ua.user_id = up.user_id
                    ORDER BY ua.created_at DESC
                """)
            
            users = []
            
            for row in cursor.fetchall():
                user_id = row[0]
                
                # 獲取對話數
                if use_postgresql:
                    cursor.execute("""
                        SELECT COUNT(*) FROM conversation_summaries WHERE user_id = %s
                    """, (user_id,))
                else:
                    cursor.execute("""
                        SELECT COUNT(*) FROM conversation_summaries WHERE user_id = ?
                    """, (user_id,))
                conversation_count = cursor.fetchone()[0]
                
                # 獲取腳本數
                if use_postgresql:
                    cursor.execute("""
                        SELECT COUNT(*) FROM user_scripts WHERE user_id = %s
                    """, (user_id,))
                else:
                    cursor.execute("""
                        SELECT COUNT(*) FROM user_scripts WHERE user_id = ?
                    """, (user_id,))
                script_count = cursor.fetchone()[0]
                
                # 格式化日期（台灣時區 UTC+8）
                created_at = row[5]
                if created_at:
                    try:
                        from datetime import timezone, timedelta
                        if isinstance(created_at, datetime):
                            dt = created_at
                        elif isinstance(created_at, str):
                            dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                        else:
                            dt = None
                        
                        if dt:
                            # 轉換為台灣時區 (UTC+8)
                            taiwan_tz = timezone(timedelta(hours=8))
                            if dt.tzinfo is None:
                                dt = dt.replace(tzinfo=timezone.utc)
                            dt_taiwan = dt.astimezone(taiwan_tz)
                            created_at = dt_taiwan.strftime('%Y/%m/%d %H:%M')
                    except Exception as e:
                        print(f"格式化日期時出錯: {e}")
                        pass
                
                users.append({
                    "user_id": user_id,
                    "google_id": row[1],
                    "email": row[2],
                    "name": row[3],
                    "picture": row[4],
                    "created_at": created_at,
                    "is_subscribed": bool(row[6]) if row[6] is not None else True,  # 預設為已訂閱
                    "preferred_platform": row[7],
                    "preferred_style": row[8],
                    "preferred_duration": row[9],
                    "conversation_count": conversation_count,
                    "script_count": script_count
                })
            
            conn.close()
            return {"users": users}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)
    
    @app.put("/api/admin/users/{user_id}/subscription")
    async def update_user_subscription(user_id: str, request: Request, admin_user: str = Depends(get_admin_user)):
        """更新用戶訂閱狀態（管理員用）"""
        try:
            data = await request.json()
            is_subscribed = data.get("is_subscribed", 0)
            # 可選：設定訂閱期限（天數），預設為 30 天（1個月）
            subscription_days = data.get("subscription_days", 30)
            # 可選：管理員備註
            admin_note = data.get("admin_note", "")
            
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            # 初始化變數
            expires_dt = None
            
            if is_subscribed:
                # 啟用訂閱：更新 user_auth 並在 licenses 表中創建/更新記錄
                # 計算到期日（預設為 30 天後）
                expires_dt = get_taiwan_time() + timedelta(days=subscription_days)
                
                # 更新 user_auth 訂閱狀態
                if use_postgresql:
                    cursor.execute("""
                        UPDATE user_auth 
                            SET is_subscribed = 1, updated_at = CURRENT_TIMESTAMP
                        WHERE user_id = %s
                        """, (user_id,))
                    
                    # 更新/建立 licenses 記錄
                    # 準備 features_json（包含管理員備註）
                    features_json = None
                    if admin_note:
                        features_json = json.dumps({"admin_note": admin_note, "admin_user": admin_user})
                    
                    try:
                        cursor.execute("""
                            INSERT INTO licenses (user_id, tier, seats, expires_at, status, source, features_json, updated_at)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                            ON CONFLICT (user_id)
                            DO UPDATE SET
                                expires_at = EXCLUDED.expires_at,
                                status = EXCLUDED.status,
                                features_json = EXCLUDED.features_json,
                                updated_at = CURRENT_TIMESTAMP
                        """, (user_id, "personal", 1, expires_dt, "active", "admin_manual", features_json))
                    except Exception as e:
                        print(f"WARN: 更新 licenses 表失敗: {e}")
                else:
                    cursor.execute("""
                        UPDATE user_auth 
                            SET is_subscribed = 1, updated_at = CURRENT_TIMESTAMP
                        WHERE user_id = ?
                        """, (user_id,))
                    
                    # 更新/建立 licenses 記錄
                    # 準備 features_json（包含管理員備註）
                    features_json = None
                    if admin_note:
                        features_json = json.dumps({"admin_note": admin_note, "admin_user": admin_user})
                    
                    try:
                        cursor.execute("""
                            INSERT OR REPLACE INTO licenses
                            (user_id, tier, seats, expires_at, status, source, features_json, updated_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                        """, (user_id, "personal", 1, expires_dt.timestamp(), "active", "admin_manual", features_json))
                    except Exception as e:
                        print(f"WARN: 更新 licenses 表失敗: {e}")
            else:
                # 取消訂閱：更新 user_auth 並將 licenses 狀態設為 cancelled
                if use_postgresql:
                    cursor.execute("""
                        UPDATE user_auth 
                        SET is_subscribed = 0, updated_at = CURRENT_TIMESTAMP
                        WHERE user_id = %s
                    """, (user_id,))
                    
                    # 將 licenses 狀態設為 cancelled
                    try:
                        cursor.execute("""
                            UPDATE licenses 
                            SET status = 'cancelled', updated_at = CURRENT_TIMESTAMP
                            WHERE user_id = %s
                        """, (user_id,))
                    except Exception as e:
                        print(f"WARN: 更新 licenses 表失敗: {e}")
                else:
                    cursor.execute("""
                        UPDATE user_auth 
                        SET is_subscribed = 0, updated_at = CURRENT_TIMESTAMP
                        WHERE user_id = ?
                    """, (user_id,))
                    
                    # 將 licenses 狀態設為 cancelled
                    try:
                        cursor.execute("""
                            UPDATE licenses 
                            SET status = 'cancelled', updated_at = CURRENT_TIMESTAMP
                            WHERE user_id = ?
                        """, (user_id,))
                    except Exception as e:
                        print(f"WARN: 更新 licenses 表失敗: {e}")
            
            if not use_postgresql:
                conn.commit()
            conn.close()
            
            return {
                "success": True,
                "message": f"訂閱狀態已{'啟用' if is_subscribed else '取消'}",
                "user_id": user_id,
                "is_subscribed": bool(is_subscribed),
                "expires_at": str(expires_dt) if is_subscribed else None
            }
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)
    
    @app.get("/api/admin/user/{user_id}/data")
    async def get_user_complete_data(user_id: str, admin_user: str = Depends(get_admin_user)):
        """獲取指定用戶的完整資料（管理員用）"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            # 用戶基本資料
            if use_postgresql:
                cursor.execute("""
                    SELECT ua.google_id, ua.email, ua.name, ua.picture, ua.created_at,
                           up.preferred_platform, up.preferred_style, up.preferred_duration, up.content_preferences
                    FROM user_auth ua
                    LEFT JOIN user_profiles up ON ua.user_id = up.user_id
                    WHERE ua.user_id = %s
                """, (user_id,))
            else:
                cursor.execute("""
                    SELECT ua.google_id, ua.email, ua.name, ua.picture, ua.created_at,
                           up.preferred_platform, up.preferred_style, up.preferred_duration, up.content_preferences
                    FROM user_auth ua
                    LEFT JOIN user_profiles up ON ua.user_id = up.user_id
                    WHERE ua.user_id = ?
                """, (user_id,))
            
            user_data = cursor.fetchone()
            if not user_data:
                return JSONResponse({"error": "用戶不存在"}, status_code=404)
            
            # 帳號定位記錄
            if use_postgresql:
                cursor.execute("""
                    SELECT id, record_number, content, created_at
                    FROM positioning_records
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                """, (user_id,))
            else:
                cursor.execute("""
                    SELECT id, record_number, content, created_at
                    FROM positioning_records
                    WHERE user_id = ?
                    ORDER BY created_at DESC
                """, (user_id,))
            positioning_records = cursor.fetchall()
            
            # 腳本記錄
            if use_postgresql:
                cursor.execute("""
                    SELECT id, script_name, title, content, script_data, platform, topic, profile, created_at
                    FROM user_scripts
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                """, (user_id,))
            else:
                cursor.execute("""
                    SELECT id, script_name, title, content, script_data, platform, topic, profile, created_at
                    FROM user_scripts
                    WHERE user_id = ?
                    ORDER BY created_at DESC
                """, (user_id,))
            script_records = cursor.fetchall()
            
            # 生成記錄
            if use_postgresql:
                cursor.execute("""
                    SELECT id, content, platform, topic, created_at
                    FROM generations
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                """, (user_id,))
            else:
                cursor.execute("""
                    SELECT id, content, platform, topic, created_at
                    FROM generations
                    WHERE user_id = ?
                    ORDER BY created_at DESC
                """, (user_id,))
            generation_records = cursor.fetchall()
            
            # 對話摘要
            if use_postgresql:
                cursor.execute("""
                    SELECT id, summary, conversation_type, created_at
                    FROM conversation_summaries
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                """, (user_id,))
            else:
                cursor.execute("""
                    SELECT id, summary, conversation_type, created_at
                    FROM conversation_summaries
                    WHERE user_id = ?
                    ORDER BY created_at DESC
                """, (user_id,))
            conversation_summaries = cursor.fetchall()
            
            # 用戶偏好
            if use_postgresql:
                cursor.execute("""
                    SELECT preference_type, preference_value, confidence_score, created_at
                    FROM user_preferences
                    WHERE user_id = %s
                    ORDER BY confidence_score DESC
                """, (user_id,))
            else:
                cursor.execute("""
                    SELECT preference_type, preference_value, confidence_score, created_at
                    FROM user_preferences
                    WHERE user_id = ?
                    ORDER BY confidence_score DESC
                """, (user_id,))
            user_preferences = cursor.fetchall()
            
            # 用戶行為
            if use_postgresql:
                cursor.execute("""
                    SELECT behavior_type, behavior_data, created_at
                    FROM user_behaviors
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                """, (user_id,))
            else:
                cursor.execute("""
                    SELECT behavior_type, behavior_data, created_at
                    FROM user_behaviors
                    WHERE user_id = ?
                    ORDER BY created_at DESC
                """, (user_id,))
            user_behaviors = cursor.fetchall()
            
            # 獲取訂單記錄
            if use_postgresql:
                cursor.execute("""
                    SELECT id, order_id, plan_type, amount, currency, payment_method, 
                           payment_status, paid_at, expires_at, invoice_number, created_at
                    FROM orders 
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                """, (user_id,))
            else:
                cursor.execute("""
                    SELECT id, order_id, plan_type, amount, currency, payment_method, 
                           payment_status, paid_at, expires_at, invoice_number, created_at
                    FROM orders 
                    WHERE user_id = ?
                    ORDER BY created_at DESC
                """, (user_id,))
            
            orders = []
            for row in cursor.fetchall():
                orders.append({
                    "id": row[0],
                    "order_id": row[1],
                    "plan_type": row[2],
                    "amount": row[3],
                    "currency": row[4],
                    "payment_method": row[5],
                    "payment_status": row[6],
                    "paid_at": str(row[7]) if row[7] else None,
                    "expires_at": str(row[8]) if row[8] else None,
                    "invoice_number": row[9],
                    "created_at": str(row[10]) if row[10] else None
                })
            
            # 獲取授權資訊
            if use_postgresql:
                cursor.execute("""
                    SELECT tier, seats, source, start_at, expires_at, status
                    FROM licenses 
                    WHERE user_id = %s AND status = 'active'
                    ORDER BY created_at DESC
                    LIMIT 1
                """, (user_id,))
            else:
                cursor.execute("""
                    SELECT tier, seats, source, start_at, expires_at, status
                    FROM licenses 
                    WHERE user_id = ? AND status = 'active'
                    ORDER BY created_at DESC
                    LIMIT 1
                """, (user_id,))
            
            license_row = cursor.fetchone()
            license = None
            if license_row:
                license = {
                    "tier": license_row[0],
                    "seats": license_row[1],
                    "source": license_row[2],
                    "start_at": str(license_row[3]) if license_row[3] else None,
                    "expires_at": str(license_row[4]) if license_row[4] else None,
                    "status": license_row[5]
                }
            
            conn.close()
            
            return {
                "user_info": {
                    "user_id": user_id,
                    "google_id": user_data[0],
                    "email": user_data[1],
                    "name": user_data[2],
                    "picture": user_data[3],
                    "created_at": user_data[4],
                    "preferred_platform": user_data[5],
                    "preferred_style": user_data[6],
                    "preferred_duration": user_data[7],
                    "content_preferences": json.loads(user_data[8]) if user_data[8] else None
                },
                "orders": orders,
                "license": license,
                "positioning_records": [
                    {
                        "id": record[0],
                        "record_number": record[1],
                        "content": record[2],
                        "created_at": record[3]
                    } for record in positioning_records
                ],
                "script_records": [
                    {
                        "id": record[0],
                        "script_name": record[1],
                        "title": record[2],
                        "content": record[3],
                        "script_data": json.loads(record[4]) if record[4] else {},
                        "platform": record[5],
                        "topic": record[6],
                        "profile": record[7],
                        "created_at": record[8]
                    } for record in script_records
                ],
                "generation_records": [
                    {
                        "id": record[0],
                        "content": record[1],
                        "platform": record[2],
                        "topic": record[3],
                        "created_at": record[4]
                    } for record in generation_records
                ],
                "conversation_summaries": [
                    {
                        "id": record[0],
                        "summary": record[1],
                        "conversation_type": record[2],
                        "created_at": record[3]
                    } for record in conversation_summaries
                ],
                "user_preferences": [
                    {
                        "preference_type": record[0],
                        "preference_value": record[1],
                        "confidence_score": record[2],
                        "created_at": record[3]
                    } for record in user_preferences
                ],
                "user_behaviors": [
                    {
                        "behavior_type": record[0],
                        "behavior_data": record[1],
                        "created_at": record[2]
                    } for record in user_behaviors
                ]
            }
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)
    
    @app.get("/api/admin/statistics")
    async def get_admin_statistics(admin_user: str = Depends(get_admin_user)):
        """獲取系統統計資料（管理員用）"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # 判斷資料庫類型
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            # 用戶總數
            cursor.execute("SELECT COUNT(*) FROM user_auth")
            total_users = cursor.fetchone()[0]
            
            # 今日新增用戶（兼容 SQLite 和 PostgreSQL）
            if use_postgresql:
                cursor.execute("""
                    SELECT COUNT(*) FROM user_auth 
                    WHERE created_at::date = CURRENT_DATE
                """)
            else:
                cursor.execute("""
                    SELECT COUNT(*) FROM user_auth 
                    WHERE DATE(created_at) = DATE('now')
                """)
            today_users = cursor.fetchone()[0]
            
            # 腳本總數
            cursor.execute("SELECT COUNT(*) FROM user_scripts")
            total_scripts = cursor.fetchone()[0]
            
            # 帳號定位總數
            cursor.execute("SELECT COUNT(*) FROM positioning_records")
            total_positioning = cursor.fetchone()[0]
            
            # 生成內容總數
            cursor.execute("SELECT COUNT(*) FROM generations")
            total_generations = cursor.fetchone()[0]
            
            # 對話摘要總數
            cursor.execute("SELECT COUNT(*) FROM conversation_summaries")
            total_conversations = cursor.fetchone()[0]
            
            # 平台使用統計
            cursor.execute("""
                SELECT platform, COUNT(*) as count
                FROM user_scripts
                WHERE platform IS NOT NULL
                GROUP BY platform
                ORDER BY count DESC
            """)
            platform_stats = cursor.fetchall()
            
            # 最近活躍用戶（7天內）（兼容 SQLite 和 PostgreSQL）
            if use_postgresql:
                cursor.execute("""
                    SELECT COUNT(DISTINCT user_id) 
                    FROM user_scripts 
                    WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL '7 days'
                """)
            else:
                cursor.execute("""
                    SELECT COUNT(DISTINCT user_id) 
                    FROM user_scripts 
                    WHERE created_at >= datetime('now', '-7 days')
                """)
            active_users_7d = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                "total_users": total_users,
                "today_users": today_users,
                "total_scripts": total_scripts,
                "total_positioning": total_positioning,
                "total_generations": total_generations,
                "total_conversations": total_conversations,
                "active_users_7d": active_users_7d,
                "platform_stats": [
                    {"platform": stat[0], "count": stat[1]} 
                    for stat in platform_stats
                ]
            }
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)
    
    @app.get("/api/admin/mode-statistics")
    async def get_mode_statistics(admin_user: str = Depends(get_admin_user)):
        """獲取模式使用統計"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            # 獲取各模式的對話數
            cursor.execute("""
                SELECT conversation_type, COUNT(*) as count
                FROM conversation_summaries
                WHERE conversation_type IS NOT NULL
                GROUP BY conversation_type
            """)
            conversations = cursor.fetchall()
            
            # 計算各模式統計
            mode_stats = {
                "mode1_quick_generate": {"count": 0, "completion_rate": 0},
                "mode2_ai_consultant": {"count": 0, "avg_turns": 0},
                "mode3_ip_planning": {"count": 0, "profiles_generated": 0}
            }
            
            # 根據對話類型分類
            for conv_type, count in conversations:
                if conv_type == "account_positioning":
                    mode_stats["mode1_quick_generate"]["count"] = count
                elif conv_type in ["topic_selection", "script_generation"]:
                    mode_stats["mode2_ai_consultant"]["count"] += count
                elif conv_type == "general_consultation":
                    mode_stats["mode2_ai_consultant"]["count"] += count
                elif conv_type == "ip_planning":
                    mode_stats["mode3_ip_planning"]["count"] += count
            
            # 計算 Mode1 完成率：有進行帳號定位對話且有保存腳本的用戶比例
            if mode_stats["mode1_quick_generate"]["count"] > 0:
                # 獲取進行過帳號定位對話的用戶數
                cursor.execute("""
                    SELECT COUNT(DISTINCT user_id) as user_count
                    FROM conversation_summaries
                    WHERE conversation_type = 'account_positioning'
                """)
                positioning_users_result = cursor.fetchone()
                total_users = positioning_users_result[0] if positioning_users_result and positioning_users_result[0] else 0
                
                # 獲取有保存腳本的用戶數（這些用戶完成了整個流程）
                cursor.execute("""
                    SELECT COUNT(DISTINCT cs.user_id) as completion_count
                    FROM conversation_summaries cs
                    INNER JOIN user_scripts us ON cs.user_id = us.user_id
                    WHERE cs.conversation_type = 'account_positioning'
                    AND us.created_at >= cs.created_at
                """)
                completion_result = cursor.fetchone()
                completion_count = completion_result[0] if completion_result and completion_result[0] else 0
                
                # 計算完成率
                if total_users > 0:
                    completion_rate = round((completion_count / total_users) * 100, 1)
                    mode_stats["mode1_quick_generate"]["completion_rate"] = completion_rate
                else:
                    mode_stats["mode1_quick_generate"]["completion_rate"] = 0
            else:
                mode_stats["mode1_quick_generate"]["completion_rate"] = 0
            
            # 從長期記憶表統計 IP 人設規劃的使用次數（如果 conversation_summaries 沒有記錄）
            # 因為 IP 人設規劃主要通過長期記憶 API 記錄
            cursor.execute("""
                SELECT COUNT(DISTINCT session_id) as session_count, COUNT(DISTINCT user_id) as user_count
                FROM long_term_memory
                WHERE conversation_type = 'ip_planning'
            """)
            ip_planning_stats = cursor.fetchone()
            if ip_planning_stats:
                session_count = ip_planning_stats[0] if ip_planning_stats[0] else 0
                # 如果 conversation_summaries 沒有記錄，使用長期記憶的會話數
                if mode_stats["mode3_ip_planning"]["count"] == 0 and session_count > 0:
                    mode_stats["mode3_ip_planning"]["count"] = session_count
            
            # 統計 IP 人設規劃生成的 Profile 數量（從 user_profiles 表或相關記錄）
            cursor.execute("""
                SELECT COUNT(DISTINCT user_id) as profile_count
                FROM long_term_memory
                WHERE conversation_type = 'ip_planning'
            """)
            profile_result = cursor.fetchone()
            if profile_result and profile_result[0]:
                mode_stats["mode3_ip_planning"]["profiles_generated"] = profile_result[0]
            
            # 獲取各模式的時間分布（分別統計）
            time_distribution = {
                "mode1": {"00:00-06:00": 0, "06:00-12:00": 0, "12:00-18:00": 0, "18:00-24:00": 0},
                "mode2": {"00:00-06:00": 0, "06:00-12:00": 0, "12:00-18:00": 0, "18:00-24:00": 0},
                "mode3": {"00:00-06:00": 0, "06:00-12:00": 0, "12:00-18:00": 0, "18:00-24:00": 0}
            }
            
            # 統計 Mode1（一鍵生成）的時間分布
            if use_postgresql:
                cursor.execute("""
                    SELECT DATE_TRUNC('hour', created_at) as hour, COUNT(*) as count
                    FROM conversation_summaries
                    WHERE conversation_type = 'account_positioning'
                    AND created_at >= CURRENT_TIMESTAMP - INTERVAL '30 days'
                    GROUP BY hour
                    ORDER BY hour
                """)
            else:
                cursor.execute("""
                    SELECT strftime('%H', created_at) as hour, COUNT(*) as count
                    FROM conversation_summaries
                    WHERE conversation_type = 'account_positioning'
                    AND created_at >= datetime('now', '-30 days')
                    GROUP BY hour
                    ORDER BY hour
                """)
            
            for row in cursor.fetchall():
                try:
                    if use_postgresql:
                        hour_str = row[0].strftime('%H')
                    else:
                        hour_str = str(row[0])[:2]
                    hour = int(hour_str)
                except:
                    hour = 0
                
                count = row[1]
                if 0 <= hour < 6:
                    time_distribution["mode1"]["00:00-06:00"] += count
                elif 6 <= hour < 12:
                    time_distribution["mode1"]["06:00-12:00"] += count
                elif 12 <= hour < 18:
                    time_distribution["mode1"]["12:00-18:00"] += count
                else:
                    time_distribution["mode1"]["18:00-24:00"] += count
            
            # 統計 Mode2（AI顧問）的時間分布
            if use_postgresql:
                cursor.execute("""
                    SELECT DATE_TRUNC('hour', created_at) as hour, COUNT(*) as count
                    FROM conversation_summaries
                    WHERE conversation_type IN ('topic_selection', 'script_generation', 'general_consultation')
                    AND created_at >= CURRENT_TIMESTAMP - INTERVAL '30 days'
                    GROUP BY hour
                    ORDER BY hour
                """)
            else:
                cursor.execute("""
                    SELECT strftime('%H', created_at) as hour, COUNT(*) as count
                    FROM conversation_summaries
                    WHERE conversation_type IN ('topic_selection', 'script_generation', 'general_consultation')
                    AND created_at >= datetime('now', '-30 days')
                    GROUP BY hour
                    ORDER BY hour
                """)
            
            for row in cursor.fetchall():
                try:
                    if use_postgresql:
                        hour_str = row[0].strftime('%H')
                    else:
                        hour_str = str(row[0])[:2]
                    hour = int(hour_str)
                except:
                    hour = 0
                
                count = row[1]
                if 0 <= hour < 6:
                    time_distribution["mode2"]["00:00-06:00"] += count
                elif 6 <= hour < 12:
                    time_distribution["mode2"]["06:00-12:00"] += count
                elif 12 <= hour < 18:
                    time_distribution["mode2"]["12:00-18:00"] += count
                else:
                    time_distribution["mode2"]["18:00-24:00"] += count
            
            # 統計 Mode3（IP人設規劃）的時間分布（從 long_term_memory 表）
            if use_postgresql:
                cursor.execute("""
                    SELECT DATE_TRUNC('hour', created_at) as hour, COUNT(DISTINCT session_id) as count
                    FROM long_term_memory
                    WHERE conversation_type = 'ip_planning'
                    AND created_at >= CURRENT_TIMESTAMP - INTERVAL '30 days'
                    GROUP BY hour
                    ORDER BY hour
                """)
            else:
                cursor.execute("""
                    SELECT strftime('%H', created_at) as hour, COUNT(DISTINCT session_id) as count
                    FROM long_term_memory
                    WHERE conversation_type = 'ip_planning'
                    AND created_at >= datetime('now', '-30 days')
                    GROUP BY hour
                    ORDER BY hour
                """)
            
            for row in cursor.fetchall():
                try:
                    if use_postgresql:
                        hour_str = row[0].strftime('%H')
                    else:
                        hour_str = str(row[0])[:2]
                    hour = int(hour_str)
                except:
                    hour = 0
                
                count = row[1]
                if 0 <= hour < 6:
                    time_distribution["mode3"]["00:00-06:00"] += count
                elif 6 <= hour < 12:
                    time_distribution["mode3"]["06:00-12:00"] += count
                elif 12 <= hour < 18:
                    time_distribution["mode3"]["12:00-18:00"] += count
                else:
                    time_distribution["mode3"]["18:00-24:00"] += count
            
            conn.close()
            
            return {
                "mode_stats": mode_stats,
                "time_distribution": time_distribution
            }
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)
    
    @app.get("/api/admin/conversations")
    async def get_all_conversations(
        admin_user: str = Depends(get_admin_user),
        page: int = 1,
        limit: int = 100,
        conversation_type: Optional[str] = None
    ):
        """獲取所有對話記錄（管理員用）
        
        Args:
            page: 頁碼（從1開始）
            limit: 每頁記錄數（默認100）
            conversation_type: 可選的對話類型篩選
        """
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            # 計算偏移量
            offset = (page - 1) * limit
            
            # 構建查詢條件
            where_clause = ""
            params = []
            
            if conversation_type:
                where_clause = "WHERE cs.conversation_type = %s" if use_postgresql else "WHERE cs.conversation_type = ?"
                params.append(conversation_type)
            
            # 獲取總數（用於分頁）
            if use_postgresql:
                count_query = f"SELECT COUNT(*) FROM conversation_summaries cs {where_clause}"
            else:
                count_query = f"SELECT COUNT(*) FROM conversation_summaries cs {where_clause}"
            
            cursor.execute(count_query, params if params else None)
            total_count = cursor.fetchone()[0]
            
            # 獲取對話記錄
            if use_postgresql:
                query = f"""
                    SELECT cs.id, cs.user_id, cs.conversation_type, cs.summary, cs.message_count, cs.created_at, 
                           ua.name, ua.email
                    FROM conversation_summaries cs
                    LEFT JOIN user_auth ua ON cs.user_id = ua.user_id
                    {where_clause}
                    ORDER BY cs.created_at DESC
                    LIMIT %s OFFSET %s
                """
                cursor.execute(query, params + [limit, offset])
            else:
                query = f"""
                    SELECT cs.id, cs.user_id, cs.conversation_type, cs.summary, cs.message_count, cs.created_at, 
                           ua.name, ua.email
                    FROM conversation_summaries cs
                    LEFT JOIN user_auth ua ON cs.user_id = ua.user_id
                    {where_clause}
                    ORDER BY cs.created_at DESC
                    LIMIT ? OFFSET ?
                """
                cursor.execute(query, params + [limit, offset])
            
            conversations = []
            conv_type_map = {
                "account_positioning": "帳號定位",
                "topic_selection": "選題討論",
                "script_generation": "腳本生成",
                "general_consultation": "AI顧問",
                "ip_planning": "IP人設規劃"
            }
            
            for row in cursor.fetchall():
                conversations.append({
                    "id": row[0],
                    "user_id": row[1],
                    "mode": conv_type_map.get(row[2], row[2]),
                    "conversation_type": row[2],
                    "summary": row[3] or "",
                    "message_count": row[4] or 0,
                    "created_at": row[5],
                    "user_name": row[6] or "未知用戶",
                    "user_email": row[7] or ""
                })
            
            conn.close()
            
            # 計算分頁資訊
            total_pages = (total_count + limit - 1) // limit if total_count > 0 else 0
            
            return {
                "conversations": conversations,
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": total_count,
                    "total_pages": total_pages,
                    "has_next": page < total_pages,
                    "has_prev": page > 1
                }
            }
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)
    
    @app.get("/api/admin/generations")
    async def get_all_generations(admin_user: str = Depends(get_admin_user)):
        """獲取所有生成記錄"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            if use_postgresql:
                cursor.execute("""
                    SELECT g.id, g.user_id, g.platform, g.topic, g.content, g.created_at, 
                           ua.name, ua.email
                    FROM generations g
                    LEFT JOIN user_auth ua ON g.user_id = ua.user_id
                    ORDER BY g.created_at DESC
                    LIMIT 100
                """)
            else:
                cursor.execute("""
                    SELECT g.id, g.user_id, g.platform, g.topic, g.content, g.created_at, 
                           ua.name, ua.email
                    FROM generations g
                    LEFT JOIN user_auth ua ON g.user_id = ua.user_id
                    ORDER BY g.created_at DESC
                    LIMIT 100
                """)
            
            generations = []
            for row in cursor.fetchall():
                generations.append({
                    "id": row[0],
                    "user_id": row[1],
                    "user_name": row[6] or "未知用戶",
                    "user_email": row[7] or "",
                    "platform": row[2] or "未設定",
                    "topic": row[3] or "未分類",
                    "type": "生成記錄",
                    "content": row[4][:100] if row[4] else "",
                    "created_at": row[5]
                })
            
            conn.close()
            
            return {"generations": generations}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)
    
    @app.get("/api/admin/scripts")
    async def get_all_scripts(admin_user: str = Depends(get_admin_user)):
        """獲取所有腳本記錄（管理員用）"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            if use_postgresql:
                cursor.execute("""
                    SELECT us.id, us.user_id, us.script_name, us.title, us.content, us.platform, us.topic, 
                           us.created_at, ua.name, ua.email
                    FROM user_scripts us
                    LEFT JOIN user_auth ua ON us.user_id = ua.user_id
                    ORDER BY us.created_at DESC
                    LIMIT 100
                """)
            else:
                cursor.execute("""
                    SELECT us.id, us.user_id, us.script_name, us.title, us.content, us.platform, us.topic, 
                           us.created_at, ua.name, ua.email
                    FROM user_scripts us
                    LEFT JOIN user_auth ua ON us.user_id = ua.user_id
                    ORDER BY us.created_at DESC
                    LIMIT 100
                """)
            
            scripts = []
            for row in cursor.fetchall():
                scripts.append({
                    "id": row[0],
                    "user_id": row[1],
                    "name": row[2] or row[3] or "未命名腳本",
                    "title": row[3] or row[2] or "未命名腳本",
                    "content": row[4] or "",
                    "script_content": row[4] or "",
                    "platform": row[5] or "未設定",
                    "category": row[6] or "未分類",
                    "topic": row[6] or "未分類",
                    "created_at": row[7],
                    "user_name": row[8] or "未知用戶",
                    "user_email": row[9] or ""
                })
            
            conn.close()
            
            return {"scripts": scripts}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)
    
    @app.delete("/api/admin/scripts/{script_id}")
    async def delete_script_admin(script_id: int, admin_user: str = Depends(get_admin_user)):
        """刪除腳本（管理員用）"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            # 檢查腳本是否存在
            if use_postgresql:
                cursor.execute("SELECT id FROM user_scripts WHERE id = %s", (script_id,))
            else:
                cursor.execute("SELECT id FROM user_scripts WHERE id = ?", (script_id,))
            
            if not cursor.fetchone():
                conn.close()
                return JSONResponse({"error": "腳本不存在"}, status_code=404)
            
            # 刪除腳本
            if use_postgresql:
                cursor.execute("DELETE FROM user_scripts WHERE id = %s", (script_id,))
            else:
                cursor.execute("DELETE FROM user_scripts WHERE id = ?", (script_id,))
            
            if not use_postgresql:
                conn.commit()
            conn.close()
            
            return {"success": True, "message": "腳本已刪除"}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)
    
    @app.get("/api/admin/ip-planning")
    async def get_all_ip_planning_results(admin_user: str = Depends(get_admin_user), result_type: Optional[str] = None):
        """獲取所有 IP 人設規劃結果（管理員用）"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            if result_type:
                # 獲取特定類型的結果
                if use_postgresql:
                    cursor.execute("""
                        SELECT ipr.id, ipr.user_id, ipr.result_type, ipr.title, ipr.content, 
                               ipr.created_at, ipr.updated_at, ua.name, ua.email
                        FROM ip_planning_results ipr
                        LEFT JOIN user_auth ua ON ipr.user_id = ua.user_id
                        WHERE ipr.result_type = %s
                        ORDER BY ipr.created_at DESC
                        LIMIT 100
                    """, (result_type,))
                else:
                    cursor.execute("""
                        SELECT ipr.id, ipr.user_id, ipr.result_type, ipr.title, ipr.content, 
                               ipr.created_at, ipr.updated_at, ua.name, ua.email
                        FROM ip_planning_results ipr
                        LEFT JOIN user_auth ua ON ipr.user_id = ua.user_id
                        WHERE ipr.result_type = ?
                        ORDER BY ipr.created_at DESC
                        LIMIT 100
                    """, (result_type,))
            else:
                # 獲取所有結果
                if use_postgresql:
                    cursor.execute("""
                        SELECT ipr.id, ipr.user_id, ipr.result_type, ipr.title, ipr.content, 
                               ipr.created_at, ipr.updated_at, ua.name, ua.email
                        FROM ip_planning_results ipr
                        LEFT JOIN user_auth ua ON ipr.user_id = ua.user_id
                        ORDER BY ipr.created_at DESC
                        LIMIT 100
                    """)
                else:
                    cursor.execute("""
                        SELECT ipr.id, ipr.user_id, ipr.result_type, ipr.title, ipr.content, 
                               ipr.created_at, ipr.updated_at, ua.name, ua.email
                        FROM ip_planning_results ipr
                        LEFT JOIN user_auth ua ON ipr.user_id = ua.user_id
                        ORDER BY ipr.created_at DESC
                        LIMIT 100
                    """)
            
            results = []
            for row in cursor.fetchall():
                results.append({
                    "id": row[0],
                    "user_id": row[1],
                    "result_type": row[2],
                    "title": row[3] or "",
                    "content": row[4] or "",
                    "created_at": row[5],
                    "updated_at": row[6],
                    "user_name": row[7] or "未知用戶",
                    "user_email": row[8] or ""
                })
            
            conn.close()
            return {"results": results}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)
    
    @app.get("/api/admin/platform-statistics")
    async def get_platform_statistics(admin_user: str = Depends(get_admin_user)):
        """獲取平台使用統計"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            cursor.execute("""
                SELECT platform, COUNT(*) as count
                FROM user_scripts
                WHERE platform IS NOT NULL
                GROUP BY platform
                ORDER BY count DESC
            """)
            
            platform_stats = [{"platform": row[0], "count": row[1]} for row in cursor.fetchall()]
            
            conn.close()
            
            return {"platform_stats": platform_stats}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)
    
    @app.get("/api/admin/user-activities")
    async def get_user_activities(admin_user: str = Depends(get_admin_user)):
        """獲取最近用戶活動"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # 獲取最近10個活動
            activities = []
            
            # 最近註冊的用戶
            cursor.execute("""
                SELECT user_id, name, created_at
                FROM user_auth
                ORDER BY created_at DESC
                LIMIT 3
            """)
            for row in cursor.fetchall():
                activities.append({
                    "type": "新用戶註冊",
                    "user_id": row[0],
                    "name": row[1] or "未知用戶",
                    "time": row[2],
                    "icon": "👤"
                })
            
            # 最近的腳本生成
            cursor.execute("""
                SELECT us.user_id, us.title, us.created_at, ua.name
                FROM user_scripts us
                LEFT JOIN user_auth ua ON us.user_id = ua.user_id
                ORDER BY us.created_at DESC
                LIMIT 3
            """)
            for row in cursor.fetchall():
                activities.append({
                    "type": "新腳本生成",
                    "user_id": row[0],
                    "name": row[3] or "未知用戶",
                    "title": row[1] or "未命名腳本",
                    "time": row[2],
                    "icon": "📝"
                })
            
            # 最近的對話
            cursor.execute("""
                SELECT cs.user_id, cs.conversation_type, cs.created_at, ua.name
                FROM conversation_summaries cs
                LEFT JOIN user_auth ua ON cs.user_id = ua.user_id
                ORDER BY cs.created_at DESC
                LIMIT 3
            """)
            for row in cursor.fetchall():
                mode_map = {
                    "account_positioning": "帳號定位",
                    "topic_selection": "選題討論",
                    "script_generation": "腳本生成",
                    "general_consultation": "AI顧問對話"
                }
                activities.append({
                    "type": f"{mode_map.get(row[1], '對話')}",
                    "user_id": row[0],
                    "name": row[3] or "未知用戶",
                    "time": row[2],
                    "icon": "💬"
                })
            
            # 按時間排序
            activities.sort(key=lambda x: x['time'], reverse=True)
            activities = activities[:10]
            
            conn.close()
            
            return {"activities": activities}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)
    
    @app.get("/api/admin/analytics-data")
    async def get_analytics_data(admin_user: str = Depends(get_admin_user)):
        """獲取分析頁面所需的所有數據"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            # 平台使用分布
            cursor.execute("""
                SELECT platform, COUNT(*) as count
                FROM user_scripts
                WHERE platform IS NOT NULL
                GROUP BY platform
                ORDER BY count DESC
            """)
            platform_stats = cursor.fetchall()
            platform_labels = [row[0] for row in platform_stats]
            platform_data = [row[1] for row in platform_stats]
            
            # 時間段使用分析（最近30天）
            if use_postgresql:
                cursor.execute("""
                    SELECT DATE_TRUNC('day', created_at) as date, COUNT(*) as count
                    FROM user_scripts
                    WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL '30 days'
                    GROUP BY date
                    ORDER BY date
                """)
            else:
                cursor.execute("""
                    SELECT DATE(created_at) as date, COUNT(*) as count
                    FROM user_scripts
                    WHERE created_at >= datetime('now', '-30 days')
                    GROUP BY date
                    ORDER BY date
                """)
            
            daily_usage = {}
            for row in cursor.fetchall():
                try:
                    if use_postgresql:
                        # PostgreSQL 返回 date 對象
                        day_name = row[0].strftime('%a')
                    else:
                        # SQLite 返回 'YYYY-MM-DD' 字符串
                        from datetime import datetime
                        date_str = str(row[0])
                        day_obj = datetime.strptime(date_str, '%Y-%m-%d')
                        day_name = day_obj.strftime('%a')
                except:
                    day_name = 'Mon'
                
                daily_usage[day_name] = daily_usage.get(day_name, 0) + row[1]
            
            # 內容類型分布（根據 topic 分類）
            cursor.execute("""
                SELECT topic, COUNT(*) as count
                FROM user_scripts
                WHERE topic IS NOT NULL AND topic != ''
                GROUP BY topic
                ORDER BY count DESC
                LIMIT 5
            """)
            content_types = cursor.fetchall()
            content_labels = [row[0] for row in content_types]
            content_data = [row[1] for row in content_types]
            
            # 用戶活躍度（最近4週）
            weekly_activity = []
            for i in range(4):
                if use_postgresql:
                    cursor.execute(f"""
                        SELECT COUNT(DISTINCT user_id)
                        FROM user_scripts
                        WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL '{7 * (i + 1)} days'
                          AND created_at < CURRENT_TIMESTAMP - INTERVAL '{7 * i} days'
                    """)
                else:
                    cursor.execute(f"""
                        SELECT COUNT(DISTINCT user_id)
                        FROM user_scripts
                        WHERE created_at >= datetime('now', '-{7 * (i + 1)} days')
                          AND created_at < datetime('now', '-{7 * i} days')
                    """)
                count = cursor.fetchone()[0]
                weekly_activity.append(count)
            
            conn.close()
            
            return {
                "platform": {
                    "labels": platform_labels,
                    "data": platform_data
                },
                "time_usage": {
                    "labels": ['週一', '週二', '週三', '週四', '週五', '週六', '週日'],
                    "data": [
                        daily_usage.get('Mon', 0),
                        daily_usage.get('Tue', 0),
                        daily_usage.get('Wed', 0),
                        daily_usage.get('Thu', 0),
                        daily_usage.get('Fri', 0),
                        daily_usage.get('Sat', 0),
                        daily_usage.get('Sun', 0)
                    ]
                },
                "activity": {
                    "labels": ['第1週', '第2週', '第3週', '第4週'],
                    "data": weekly_activity
                },
                "content_type": {
                    "labels": content_labels,
                    "data": content_data
                }
            }
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)
    
    @app.get("/api/admin/export/{export_type}")
    @rate_limit("10/minute")
    async def export_csv(export_type: str, request: Request, admin_user: str = Depends(get_admin_user)):
        """匯出 CSV 檔案"""
        import csv
        import io
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # 根據匯出類型選擇不同的數據
            if export_type == "users":
                cursor.execute("""
                    SELECT user_id, name, email, created_at, is_subscribed
                    FROM user_auth
                    ORDER BY created_at DESC
                """)
                
                # 創建 CSV
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow(['用戶ID', '姓名', 'Email', '註冊時間', '是否訂閱'])
                for row in cursor.fetchall():
                    writer.writerow(row)
                output.seek(0)
                
                return Response(
                    content=output.getvalue(),
                    media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=users.csv"}
                )
            
            elif export_type == "scripts":
                cursor.execute("""
                    SELECT us.id, ua.name, us.platform, us.topic, us.title, us.created_at
                    FROM user_scripts us
                    LEFT JOIN user_auth ua ON us.user_id = ua.user_id
                    ORDER BY us.created_at DESC
                """)
                
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow(['腳本ID', '用戶名稱', '平台', '主題', '標題', '創建時間'])
                for row in cursor.fetchall():
                    writer.writerow(row)
                output.seek(0)
                
                return Response(
                    content=output.getvalue(),
                    media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=scripts.csv"}
                )
            
            elif export_type == "conversations":
                cursor.execute("""
                    SELECT cs.id, ua.name, cs.conversation_type, cs.summary, cs.created_at
                    FROM conversation_summaries cs
                    LEFT JOIN user_auth ua ON cs.user_id = ua.user_id
                    ORDER BY cs.created_at DESC
                """)
                
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow(['對話ID', '用戶名稱', '對話類型', '摘要', '創建時間'])
                for row in cursor.fetchall():
                    writer.writerow(row)
                output.seek(0)
                
                return Response(
                    content=output.getvalue(),
                    media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=conversations.csv"}
                )
            
            elif export_type == "generations":
                cursor.execute("""
                    SELECT g.id, ua.name, g.platform, g.topic, g.content, g.created_at
                    FROM generations g
                    LEFT JOIN user_auth ua ON g.user_id = ua.user_id
                    ORDER BY g.created_at DESC
                """)
                
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow(['生成ID', '用戶名稱', '平台', '主題', '內容', '創建時間'])
                for row in cursor.fetchall():
                    writer.writerow(row)
                output.seek(0)
                
                return Response(
                    content=output.getvalue(),
                    media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=generations.csv"}
                )
            
            elif export_type == "orders":
                database_url = os.getenv("DATABASE_URL")
                use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
                
                if use_postgresql:
                    cursor.execute("""
                        SELECT o.id, ua.name, ua.email, o.amount, o.status, o.payment_method, o.created_at, o.updated_at
                        FROM orders o
                        LEFT JOIN user_auth ua ON o.user_id = ua.user_id
                        ORDER BY o.created_at DESC
                    """)
                else:
                    cursor.execute("""
                        SELECT o.id, ua.name, ua.email, o.amount, o.status, o.payment_method, o.created_at, o.updated_at
                        FROM orders o
                        LEFT JOIN user_auth ua ON o.user_id = ua.user_id
                        ORDER BY o.created_at DESC
                    """)
                
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow(['訂單ID', '用戶名稱', 'Email', '金額', '狀態', '支付方式', '創建時間', '更新時間'])
                for row in cursor.fetchall():
                    writer.writerow(row)
                output.seek(0)
                
                return Response(
                    content=output.getvalue(),
                    media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=orders.csv"}
                )
            
            elif export_type == "long-term-memory":
                database_url = os.getenv("DATABASE_URL")
                use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
                
                if use_postgresql:
                    cursor.execute("""
                        SELECT ltm.id, ua.name, ltm.user_id, ltm.session_id, ltm.conversation_type, 
                               ltm.role, ltm.content, ltm.created_at
                        FROM long_term_memory ltm
                        LEFT JOIN user_auth ua ON ltm.user_id = ua.user_id
                        ORDER BY ltm.created_at DESC
                        LIMIT 10000
                    """)
                else:
                    cursor.execute("""
                        SELECT ltm.id, ua.name, ltm.user_id, ltm.session_id, ltm.conversation_type, 
                               ltm.role, ltm.content, ltm.created_at
                        FROM long_term_memory ltm
                        LEFT JOIN user_auth ua ON ltm.user_id = ua.user_id
                        ORDER BY ltm.created_at DESC
                        LIMIT 10000
                    """)
                
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow(['ID', '用戶名稱', '用戶ID', '會話ID', '對話類型', '角色', '內容', '創建時間'])
                for row in cursor.fetchall():
                    # 處理內容可能很長的情況
                    content = str(row[6]) if row[6] else ""
                    if len(content) > 1000:
                        content = content[:1000] + "..."
                    row_list = list(row[:6]) + [content] + [row[7]]
                    writer.writerow(row_list)
                output.seek(0)
                
                return Response(
                    content=output.getvalue(),
                    media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=long-term-memory.csv"}
                )
            
            else:
                return JSONResponse({"error": "無效的匯出類型"}, status_code=400)
        
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)
    
    @app.post("/api/admin/import/{import_type}")
    async def import_csv(import_type: str, request: Request, admin_user: str = Depends(get_admin_user)):
        """匯入 CSV 檔案"""
        import csv
        import io
        
        try:
            # 獲取上傳的檔案
            form_data = await request.form()
            file = form_data.get("file")
            mode = form_data.get("mode", "add")  # add 或 replace
            
            if not file:
                return JSONResponse({"error": "未提供檔案"}, status_code=400)
            
            # 讀取檔案內容
            file_content = await file.read()
            content_str = file_content.decode('utf-8-sig')  # 處理 BOM
            csv_reader = csv.DictReader(io.StringIO(content_str))
            
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            success_count = 0
            error_count = 0
            errors = []
            
            if import_type == "users":
                # 匯入用戶資料
                for row in csv_reader:
                    try:
                        user_id = row.get('用戶ID', '').strip()
                        name = row.get('姓名', '').strip()
                        email = row.get('Email', '').strip()
                        is_subscribed = row.get('是否訂閱', '0').strip()
                        
                        if not user_id or not email:
                            error_count += 1
                            errors.append(f"缺少必要欄位：用戶ID或Email")
                            continue
                        
                        is_subscribed_int = 1 if str(is_subscribed).lower() in ['1', 'true', 'yes', '已訂閱'] else 0
                        
                        if use_postgresql:
                            # 檢查用戶是否存在
                            cursor.execute("SELECT user_id FROM user_auth WHERE user_id = %s", (user_id,))
                            exists = cursor.fetchone()
                            
                            if exists and mode == "replace":
                                # 更新現有用戶
                                cursor.execute("""
                                    UPDATE user_auth 
                                    SET name = %s, email = %s, is_subscribed = %s, updated_at = CURRENT_TIMESTAMP
                                    WHERE user_id = %s
                                """, (name, email, is_subscribed_int, user_id))
                            elif not exists:
                                # 新增用戶
                                cursor.execute("""
                                    INSERT INTO user_auth (user_id, name, email, is_subscribed, created_at, updated_at)
                                    VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                                """, (user_id, name, email, is_subscribed_int))
                            # 如果存在且 mode == "add"，則跳過
                        else:
                            cursor.execute("SELECT user_id FROM user_auth WHERE user_id = ?", (user_id,))
                            exists = cursor.fetchone()
                            
                            if exists and mode == "replace":
                                cursor.execute("""
                                    UPDATE user_auth 
                                    SET name = ?, email = ?, is_subscribed = ?, updated_at = CURRENT_TIMESTAMP
                                    WHERE user_id = ?
                                """, (name, email, is_subscribed_int, user_id))
                            elif not exists:
                                cursor.execute("""
                                    INSERT INTO user_auth (user_id, name, email, is_subscribed, created_at, updated_at)
                                    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                                """, (user_id, name, email, is_subscribed_int))
                        
                        success_count += 1
                    except Exception as e:
                        error_count += 1
                        errors.append(f"處理用戶 {row.get('用戶ID', '未知')} 時出錯：{str(e)}")
            
            elif import_type == "scripts":
                # 匯入腳本資料
                for row in csv_reader:
                    try:
                        user_id = row.get('用戶ID', '').strip()
                        script_name = row.get('腳本名稱', row.get('標題', '')).strip()
                        title = row.get('標題', script_name).strip()
                        content = row.get('內容', '').strip()
                        platform = row.get('平台', '').strip()
                        topic = row.get('主題', '').strip()
                        
                        if not user_id or not content:
                            error_count += 1
                            errors.append(f"缺少必要欄位：用戶ID或內容")
                            continue
                        
                        if use_postgresql:
                            cursor.execute("""
                                INSERT INTO user_scripts (user_id, script_name, title, content, platform, topic, created_at)
                                VALUES (%s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                            """, (user_id, script_name, title, content, platform, topic))
                        else:
                            cursor.execute("""
                                INSERT INTO user_scripts (user_id, script_name, title, content, platform, topic, created_at)
                                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                            """, (user_id, script_name, title, content, platform, topic))
                        
                        success_count += 1
                    except Exception as e:
                        error_count += 1
                        errors.append(f"處理腳本時出錯：{str(e)}")
            
            elif import_type == "orders":
                # 匯入訂單資料
                for row in csv_reader:
                    try:
                        user_id = row.get('用戶ID', '').strip()
                        amount = row.get('金額', '0').strip()
                        status = row.get('狀態', 'pending').strip()
                        payment_method = row.get('支付方式', '').strip()
                        
                        if not user_id:
                            error_count += 1
                            errors.append(f"缺少必要欄位：用戶ID")
                            continue
                        
                        try:
                            amount_float = float(amount)
                        except:
                            amount_float = 0.0
                        
                        if use_postgresql:
                            cursor.execute("""
                                INSERT INTO orders (user_id, amount, status, payment_method, created_at, updated_at)
                                VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                            """, (user_id, amount_float, status, payment_method))
                        else:
                            cursor.execute("""
                                INSERT INTO orders (user_id, amount, status, payment_method, created_at, updated_at)
                                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                            """, (user_id, amount_float, status, payment_method))
                        
                        success_count += 1
                    except Exception as e:
                        error_count += 1
                        errors.append(f"處理訂單時出錯：{str(e)}")
            
            else:
                conn.close()
                return JSONResponse({"error": "不支援的匯入類型"}, status_code=400)
            
            if not use_postgresql:
                conn.commit()
            conn.close()
            
            return {
                "success": True,
                "success_count": success_count,
                "error_count": error_count,
                "errors": errors[:10]  # 只返回前10個錯誤
            }
            
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    # ===== n8n 自動匯出 API =====
    
    @app.post("/api/v1/export/all")
    async def export_all_data(request: Request):
        """匯出所有資料到單一 CSV 檔案（供 n8n 使用）
        
        請求格式：
        {
            "from": "2025-11-01T00:00:00Z",  # 可選：開始時間
            "to": "2025-11-02T00:00:00Z",    # 可選：結束時間
            "api_key": "your_api_key"        # 可選：API 金鑰驗證
        }
        
        回應：直接返回 CSV 檔案（所有表格合併）
        """
        import csv
        import io
        from datetime import datetime
        
        try:
            # 獲取請求參數
            data = await request.json()
            from_date = data.get("from")
            to_date = data.get("to")
            api_key = data.get("api_key")
            
            # 簡單的 API Key 驗證（可選，如果需要的話）
            # 可以從環境變數讀取預設的 API Key
            expected_api_key = os.getenv("N8N_EXPORT_API_KEY")
            if expected_api_key and api_key != expected_api_key:
                return JSONResponse(
                    {"error": "無效的 API Key"},
                    status_code=401
                )
            
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            # 構建時間過濾條件
            time_filter = ""
            time_params = []
            if from_date or to_date:
                conditions = []
                if from_date:
                    if use_postgresql:
                        conditions.append("created_at >= %s")
                    else:
                        conditions.append("created_at >= ?")
                    time_params.append(from_date)
                if to_date:
                    if use_postgresql:
                        conditions.append("created_at <= %s")
                    else:
                        conditions.append("created_at <= ?")
                    time_params.append(to_date)
                if conditions:
                    time_filter = "WHERE " + " AND ".join(conditions)
            
            # 定義統一的 CSV 欄位（包含所有表格的欄位）
            # 這樣可以確保所有資料都在同一個 CSV 中
            csv_headers = [
                '資料表',           # 標識資料來源
                '記錄ID',           # 通用 ID
                '用戶ID',           # 通用用戶 ID
                '用戶名稱',          # 用戶名稱
                'Email',            # 用戶 Email
                '平台',             # 平台資訊
                '主題',             # 主題/分類
                '標題',             # 標題
                '內容',             # 內容/摘要
                '對話類型',          # 對話類型
                '腳本ID',           # 腳本 ID
                '訂單ID',           # 訂單 ID
                '金額',             # 金額
                '狀態',             # 狀態
                '支付方式',          # 支付方式
                '是否訂閱',          # 訂閱狀態
                '創建時間',          # 創建時間
                '更新時間'           # 更新時間
            ]
            
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(csv_headers)
            
            # 1. 匯出用戶資料 (users)
            if use_postgresql:
                cursor.execute(f"""
                    SELECT user_id, name, email, created_at, updated_at, is_subscribed
                    FROM user_auth
                    {time_filter}
                    ORDER BY created_at DESC
                """, tuple(time_params))
            else:
                cursor.execute(f"""
                    SELECT user_id, name, email, created_at, updated_at, is_subscribed
                    FROM user_auth
                    {time_filter}
                    ORDER BY created_at DESC
                """, tuple(time_params))
            
            for row in cursor.fetchall():
                writer.writerow([
                    'users',           # 資料表
                    row[0],            # 記錄ID (user_id)
                    row[0],            # 用戶ID
                    row[1] or '',       # 用戶名稱
                    row[2] or '',       # Email
                    '',                # 平台
                    '',                # 主題
                    '',                # 標題
                    '',                # 內容
                    '',                # 對話類型
                    '',                # 腳本ID
                    '',                # 訂單ID
                    '',                # 金額
                    '',                # 狀態
                    '',                # 支付方式
                    '是' if row[5] else '否',  # 是否訂閱
                    str(row[3]) if row[3] else '',  # 創建時間
                    str(row[4]) if row[4] else ''   # 更新時間
                ])
            
            # 2. 匯出腳本資料 (projects/user_scripts)
            script_time_filter = time_filter.replace("created_at", "us.created_at") if time_filter else ""
            if use_postgresql:
                cursor.execute(f"""
                    SELECT us.id, us.user_id, ua.name, ua.email, us.platform, us.topic, us.title, 
                           us.content, us.created_at, us.updated_at
                    FROM user_scripts us
                    LEFT JOIN user_auth ua ON us.user_id = ua.user_id
                    {script_time_filter}
                    ORDER BY us.created_at DESC
                """, tuple(time_params))
            else:
                cursor.execute(f"""
                    SELECT us.id, us.user_id, ua.name, ua.email, us.platform, us.topic, us.title, 
                           us.content, us.created_at, us.updated_at
                    FROM user_scripts us
                    LEFT JOIN user_auth ua ON us.user_id = ua.user_id
                    {script_time_filter}
                    ORDER BY us.created_at DESC
                """, tuple(time_params))
            
            for row in cursor.fetchall():
                writer.writerow([
                    'projects',        # 資料表
                    str(row[0]),       # 記錄ID (script id)
                    row[1] or '',       # 用戶ID
                    row[2] or '',       # 用戶名稱
                    row[3] or '',       # Email
                    row[4] or '',       # 平台
                    row[5] or '',       # 主題
                    row[6] or '',       # 標題
                    (row[7] or '')[:500] if row[7] else '',  # 內容（限制長度）
                    '',                # 對話類型
                    str(row[0]),       # 腳本ID
                    '',                # 訂單ID
                    '',                # 金額
                    '',                # 狀態
                    '',                # 支付方式
                    '',                # 是否訂閱
                    str(row[8]) if row[8] else '',  # 創建時間
                    str(row[9]) if row[9] else ''   # 更新時間
                ])
            
            # 3. 匯出生成記錄 (generations)
            gen_time_filter = time_filter.replace("created_at", "g.created_at") if time_filter else ""
            if use_postgresql:
                cursor.execute(f"""
                    SELECT g.id, g.user_id, ua.name, ua.email, g.platform, g.topic, g.content, g.created_at
                    FROM generations g
                    LEFT JOIN user_auth ua ON g.user_id = ua.user_id
                    {gen_time_filter}
                    ORDER BY g.created_at DESC
                """, tuple(time_params))
            else:
                cursor.execute(f"""
                    SELECT g.id, g.user_id, ua.name, ua.email, g.platform, g.topic, g.content, g.created_at
                    FROM generations g
                    LEFT JOIN user_auth ua ON g.user_id = ua.user_id
                    {gen_time_filter}
                    ORDER BY g.created_at DESC
                """, tuple(time_params))
            
            for row in cursor.fetchall():
                writer.writerow([
                    'generations',     # 資料表
                    row[0] or '',      # 記錄ID
                    row[1] or '',      # 用戶ID
                    row[2] or '',      # 用戶名稱
                    row[3] or '',      # Email
                    row[4] or '',      # 平台
                    row[5] or '',      # 主題
                    '',               # 標題
                    (row[6] or '')[:500] if row[6] else '',  # 內容（限制長度）
                    '',               # 對話類型
                    '',               # 腳本ID
                    '',               # 訂單ID
                    '',               # 金額
                    '',               # 狀態
                    '',               # 支付方式
                    '',               # 是否訂閱
                    str(row[7]) if row[7] else '',  # 創建時間
                    ''                # 更新時間
                ])
            
            # 4. 匯出對話記錄 (conversations)
            conv_time_filter = time_filter.replace("created_at", "cs.created_at") if time_filter else ""
            if use_postgresql:
                cursor.execute(f"""
                    SELECT cs.id, cs.user_id, ua.name, ua.email, cs.conversation_type, cs.summary, cs.created_at
                    FROM conversation_summaries cs
                    LEFT JOIN user_auth ua ON cs.user_id = ua.user_id
                    {conv_time_filter}
                    ORDER BY cs.created_at DESC
                """, tuple(time_params))
            else:
                cursor.execute(f"""
                    SELECT cs.id, cs.user_id, ua.name, ua.email, cs.conversation_type, cs.summary, cs.created_at
                    FROM conversation_summaries cs
                    LEFT JOIN user_auth ua ON cs.user_id = ua.user_id
                    {conv_time_filter}
                    ORDER BY cs.created_at DESC
                """, tuple(time_params))
            
            for row in cursor.fetchall():
                writer.writerow([
                    'conversations',   # 資料表
                    str(row[0]),      # 記錄ID
                    row[1] or '',      # 用戶ID
                    row[2] or '',      # 用戶名稱
                    row[3] or '',      # Email
                    '',               # 平台
                    '',               # 主題
                    '',               # 標題
                    (row[5] or '')[:500] if row[5] else '',  # 內容（摘要）
                    row[4] or '',      # 對話類型
                    '',               # 腳本ID
                    '',               # 訂單ID
                    '',               # 金額
                    '',               # 狀態
                    '',               # 支付方式
                    '',               # 是否訂閱
                    str(row[6]) if row[6] else '',  # 創建時間
                    ''                # 更新時間
                ])
            
            # 5. 匯出訂單記錄 (payments/orders)
            order_time_filter = time_filter.replace("created_at", "o.created_at") if time_filter else ""
            if use_postgresql:
                cursor.execute(f"""
                    SELECT o.id, o.user_id, ua.name, ua.email, o.order_id, o.amount, o.payment_status, 
                           o.payment_method, o.created_at, o.updated_at
                    FROM orders o
                    LEFT JOIN user_auth ua ON o.user_id = ua.user_id
                    {order_time_filter}
                    ORDER BY o.created_at DESC
                """, tuple(time_params))
            else:
                cursor.execute(f"""
                    SELECT o.id, o.user_id, ua.name, ua.email, o.order_id, o.amount, o.payment_status, 
                           o.payment_method, o.created_at, o.updated_at
                    FROM orders o
                    LEFT JOIN user_auth ua ON o.user_id = ua.user_id
                    {order_time_filter}
                    ORDER BY o.created_at DESC
                """, tuple(time_params))
            
            for row in cursor.fetchall():
                writer.writerow([
                    'payments',        # 資料表
                    str(row[0]),       # 記錄ID
                    row[1] or '',      # 用戶ID
                    row[2] or '',      # 用戶名稱
                    row[3] or '',      # Email
                    '',               # 平台
                    '',               # 主題
                    '',               # 標題
                    '',               # 內容
                    '',               # 對話類型
                    '',               # 腳本ID
                    row[4] or '',      # 訂單ID
                    str(row[5]) if row[5] else '',  # 金額
                    row[6] or '',      # 狀態
                    row[7] or '',      # 支付方式
                    '',               # 是否訂閱
                    str(row[8]) if row[8] else '',  # 創建時間
                    str(row[9]) if row[9] else ''   # 更新時間
                ])
            
            # 6. 匯出行為記錄 (events_raw/user_behaviors)
            behavior_time_filter = time_filter.replace("created_at", "created_at") if time_filter else ""
            if use_postgresql:
                cursor.execute(f"""
                    SELECT id, user_id, behavior_type, behavior_data, created_at
                    FROM user_behaviors
                    {behavior_time_filter}
                    ORDER BY created_at DESC
                    LIMIT 10000
                """, tuple(time_params))
            else:
                cursor.execute(f"""
                    SELECT id, user_id, behavior_type, behavior_data, created_at
                    FROM user_behaviors
                    {behavior_time_filter}
                    ORDER BY created_at DESC
                    LIMIT 10000
                """, tuple(time_params))
            
            for row in cursor.fetchall():
                writer.writerow([
                    'events_raw',      # 資料表
                    str(row[0]),      # 記錄ID
                    row[1] or '',      # 用戶ID
                    '',               # 用戶名稱
                    '',               # Email
                    '',               # 平台
                    '',               # 主題
                    '',               # 標題
                    row[3] or '',      # 內容（行為資料）
                    row[2] or '',      # 對話類型（行為類型）
                    '',               # 腳本ID
                    '',               # 訂單ID
                    '',               # 金額
                    '',               # 狀態
                    '',               # 支付方式
                    '',               # 是否訂閱
                    str(row[4]) if row[4] else '',  # 創建時間
                    ''                # 更新時間
                ])
            
            conn.close()
            
            output.seek(0)
            csv_content = output.getvalue()
            
            # 生成檔案名稱（包含時間戳）
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"reelmind_export_{timestamp}.csv"
            
            return Response(
                content=csv_content.encode('utf-8-sig'),  # 使用 BOM 以支援 Excel
                media_type="text/csv; charset=utf-8",
                headers={
                    "Content-Disposition": f"attachment; filename={filename}",
                    "Content-Type": "text/csv; charset=utf-8"
                }
            )
            
        except Exception as e:
            print(f"匯出錯誤: {e}")
            import traceback
            traceback.print_exc()
            return JSONResponse(
                {"error": f"匯出失敗: {str(e)}"},
                status_code=500
            )

    @app.post("/api/v1/sheets/{export_type}")
    async def export_for_sheets(export_type: str, request: Request):
        """以 JSON 物件列表輸出指定資料類型，方便 n8n → Google Sheet。

        Body 參數：
        {
            "from": "2025-11-01T00:00:00Z",  # 可選
            "to":   "2025-11-05T23:59:59Z",  # 可選
            "api_key": "..."                 # 可選，若環境有設 N8N_EXPORT_API_KEY 則必填
        }
        回應：{
            "type": "users" | ...,
            "count": 123,
            "rows": [ {欄位: 值, ...}, ... ]
        }
        """
        try:
            data = await request.json()
            from_date = data.get("from")
            to_date = data.get("to")
            api_key = data.get("api_key")
            limit = int(data.get("limit", 10000))

            expected_api_key = os.getenv("N8N_EXPORT_API_KEY")
            if expected_api_key and api_key != expected_api_key:
                return JSONResponse({"error": "無效的 API Key"}, status_code=401)

            conn = get_db_connection()
            cursor = conn.cursor()

            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE

            def build_time_filter(column_name: str) -> tuple[str, list]:
                tf = ""
                params: list = []
                if from_date or to_date:
                    conds = []
                    if from_date:
                        conds.append(f"{column_name} >= %s" if use_postgresql else f"{column_name} >= ?")
                        params.append(from_date)
                    if to_date:
                        conds.append(f"{column_name} <= %s" if use_postgresql else f"{column_name} <= ?")
                        params.append(to_date)
                    tf = "WHERE " + " AND ".join(conds)
                return tf, params

            rows = []

            if export_type == "users":
                time_filter, params = build_time_filter("created_at")
                cursor.execute(
                    f"""
                    SELECT user_id, name, email, is_subscribed, created_at, updated_at
                    FROM user_auth
                    {time_filter}
                    ORDER BY created_at DESC
                    LIMIT {limit}
                    """,
                    tuple(params)
                )
                for r in cursor.fetchall():
                    rows.append({
                        "user_id": r[0],
                        "name": r[1] or "",
                        "email": r[2] or "",
                        "is_subscribed": bool(r[3]) if r[3] is not None else False,
                        "created_at": str(r[4]) if r[4] else "",
                        "updated_at": str(r[5]) if r[5] else ""
                    })

            elif export_type == "scripts":
                time_filter, params = build_time_filter("us.created_at")
                cursor.execute(
                    f"""
                    SELECT us.id, us.user_id, ua.name, ua.email, us.platform, us.topic, us.title,
                           us.content, us.created_at, us.updated_at
                    FROM user_scripts us
                    LEFT JOIN user_auth ua ON us.user_id = ua.user_id
                    {time_filter}
                    ORDER BY us.created_at DESC
                    LIMIT {limit}
                    """,
                    tuple(params)
                )
                for r in cursor.fetchall():
                    rows.append({
                        "id": r[0],
                        "user_id": r[1],
                        "user_name": r[2] or "",
                        "email": r[3] or "",
                        "platform": r[4] or "",
                        "topic": r[5] or "",
                        "title": r[6] or "",
                        "content": (r[7] or ""),
                        "created_at": str(r[8]) if r[8] else "",
                        "updated_at": str(r[9]) if r[9] else ""
                    })

            elif export_type == "generations":
                time_filter, params = build_time_filter("g.created_at")
                cursor.execute(
                    f"""
                    SELECT g.id, g.user_id, ua.name, ua.email, g.platform, g.topic, g.content, g.created_at
                    FROM generations g
                    LEFT JOIN user_auth ua ON g.user_id = ua.user_id
                    {time_filter}
                    ORDER BY g.created_at DESC
                    LIMIT {limit}
                    """,
                    tuple(params)
                )
                for r in cursor.fetchall():
                    rows.append({
                        "id": r[0],
                        "user_id": r[1],
                        "user_name": r[2] or "",
                        "email": r[3] or "",
                        "platform": r[4] or "",
                        "topic": r[5] or "",
                        "content": (r[6] or ""),
                        "created_at": str(r[7]) if r[7] else ""
                    })

            elif export_type == "conversations":
                time_filter, params = build_time_filter("cs.created_at")
                cursor.execute(
                    f"""
                    SELECT cs.id, cs.user_id, ua.name, ua.email, cs.conversation_type, cs.summary, cs.created_at
                    FROM conversation_summaries cs
                    LEFT JOIN user_auth ua ON cs.user_id = ua.user_id
                    {time_filter}
                    ORDER BY cs.created_at DESC
                    LIMIT {limit}
                    """,
                    tuple(params)
                )
                for r in cursor.fetchall():
                    rows.append({
                        "id": r[0],
                        "user_id": r[1],
                        "user_name": r[2] or "",
                        "email": r[3] or "",
                        "conversation_type": r[4] or "",
                        "summary": (r[5] or ""),
                        "created_at": str(r[6]) if r[6] else ""
                    })

            elif export_type == "orders":
                time_filter, params = build_time_filter("o.created_at")
                cursor.execute(
                    f"""
                    SELECT o.id, o.user_id, ua.name, ua.email, o.order_id, o.amount, o.payment_status,
                           o.payment_method, o.created_at, o.updated_at
                    FROM orders o
                    LEFT JOIN user_auth ua ON o.user_id = ua.user_id
                    {time_filter}
                    ORDER BY o.created_at DESC
                    LIMIT {limit}
                    """,
                    tuple(params)
                )
                for r in cursor.fetchall():
                    rows.append({
                        "id": r[0],
                        "user_id": r[1],
                        "user_name": r[2] or "",
                        "email": r[3] or "",
                        "order_id": r[4] or "",
                        "amount": float(r[5]) if r[5] is not None else 0.0,
                        "payment_status": r[6] or "",
                        "payment_method": r[7] or "",
                        "created_at": str(r[8]) if r[8] else "",
                        "updated_at": str(r[9]) if r[9] else ""
                    })

            elif export_type == "long-term-memory":
                time_filter, params = build_time_filter("ltm.created_at")
                cursor.execute(
                    f"""
                    SELECT ltm.id, ua.name, ltm.user_id, ltm.session_id, ltm.conversation_type,
                           ltm.role, ltm.content, ltm.created_at
                    FROM long_term_memory ltm
                    LEFT JOIN user_auth ua ON ltm.user_id = ua.user_id
                    {time_filter}
                    ORDER BY ltm.created_at DESC
                    LIMIT {limit}
                    """,
                    tuple(params)
                )
                for r in cursor.fetchall():
                    rows.append({
                        "id": r[0],
                        "user_name": r[1] or "",
                        "user_id": r[2],
                        "session_id": r[3] or "",
                        "conversation_type": r[4] or "",
                        "role": r[5] or "",
                        "content": (r[6] or ""),
                        "created_at": str(r[7]) if r[7] else ""
                    })

            else:
                conn.close()
                return JSONResponse({"error": "不支援的類型"}, status_code=400)

            conn.close()
            return {"type": export_type, "count": len(rows), "rows": rows}
        
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    # ===== OAuth 認證功能 =====
    
    @app.get("/api/auth/google")
    async def google_auth(request: Request, fb: Optional[str] = None):
        """發起 Google OAuth 認證"""
        # 透過查詢參數 fb 覆寫回跳前端（必須在白名單內）
        chosen_frontend = fb if fb in ALLOWED_FRONTENDS else FRONTEND_BASE_URL
        # 以 state 帶回前端 base，callback 取回以決定最終導向
        from urllib.parse import quote
        state_val = quote(chosen_frontend)
        auth_url = (
            f"https://accounts.google.com/o/oauth2/v2/auth?"
            f"client_id={GOOGLE_CLIENT_ID}&"
            f"redirect_uri={GOOGLE_REDIRECT_URI}&"
            f"response_type=code&"
            f"scope=openid email profile&"
            f"access_type=offline&"
            f"prompt=select_account&"
            f"state={state_val}"
        )
        
        # 除錯資訊
        print(f"DEBUG: Generated auth URL: {auth_url}")
        print(f"DEBUG: GOOGLE_CLIENT_ID: {GOOGLE_CLIENT_ID}")
        print(f"DEBUG: GOOGLE_REDIRECT_URI: {GOOGLE_REDIRECT_URI}")
        
        return {"auth_url": auth_url}

    @app.get("/api/auth/google/callback")
    async def google_callback_get(code: str = None, state: Optional[str] = None, redirect_uri: Optional[str] = None):
        """處理 Google OAuth 回調（GET 請求 - 來自 Google 重定向）"""
        try:
            # 除錯資訊
            print(f"DEBUG: OAuth callback received")
            print(f"DEBUG: Code: {code}")
            print(f"DEBUG: GOOGLE_CLIENT_ID: {GOOGLE_CLIENT_ID}")
            print(f"DEBUG: GOOGLE_CLIENT_SECRET: {GOOGLE_CLIENT_SECRET}")
            print(f"DEBUG: GOOGLE_REDIRECT_URI: {GOOGLE_REDIRECT_URI}")
            
            # 從 URL 參數獲取授權碼
            if not code:
                # 如果沒有 code，重定向到前端並顯示錯誤
                return RedirectResponse(url="https://aivideonew.zeabur.app/?error=missing_code")
            
            # 交換授權碼獲取訪問令牌
            async with httpx.AsyncClient() as client:
                token_response = await client.post(
                    "https://oauth2.googleapis.com/token",
                    data={
                        "client_id": GOOGLE_CLIENT_ID,
                        "client_secret": GOOGLE_CLIENT_SECRET,
                        "code": code,
                        "grant_type": "authorization_code",
                        "redirect_uri": GOOGLE_REDIRECT_URI,
                    }
                )
                
                if token_response.status_code != 200:
                    raise HTTPException(status_code=400, detail="Failed to get access token")
                
                token_data = token_response.json()
                access_token = token_data["access_token"]
                
                # 獲取用戶資訊
                google_user = await get_google_user_info(access_token)
                if not google_user:
                    raise HTTPException(status_code=400, detail="Failed to get user info")
                
                # 生成用戶 ID
                user_id = generate_user_id(google_user.email)
                
                # 保存或更新用戶認證資訊
                conn = get_db_connection()
                cursor = conn.cursor()
                
                database_url = os.getenv("DATABASE_URL")
                use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
                
                if use_postgresql:
                    # PostgreSQL 語法
                    from datetime import timedelta
                    expires_at_value = get_taiwan_time() + timedelta(seconds=token_data.get("expires_in", 3600))
                    
                    cursor.execute("""
                        INSERT INTO user_auth 
                        (user_id, google_id, email, name, picture, access_token, expires_at, is_subscribed, updated_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                        ON CONFLICT (user_id) 
                        DO UPDATE SET 
                            google_id = EXCLUDED.google_id,
                            email = EXCLUDED.email,
                            name = EXCLUDED.name,
                            picture = EXCLUDED.picture,
                            access_token = EXCLUDED.access_token,
                            expires_at = EXCLUDED.expires_at,
                            updated_at = CURRENT_TIMESTAMP
                    """, (
                        user_id,
                        google_user.id,
                        google_user.email,
                        google_user.name,
                        google_user.picture,
                        access_token,
                        expires_at_value,
                            0  # 新用戶預設為未訂閱
                    ))
                else:
                    # SQLite 語法
                    cursor.execute("""
                        INSERT OR REPLACE INTO user_auth 
                        (user_id, google_id, email, name, picture, access_token, expires_at, is_subscribed, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """, (
                        user_id,
                        google_user.id,
                        google_user.email,
                        google_user.name,
                        google_user.picture,
                        access_token,
                        get_taiwan_time().timestamp() + token_data.get("expires_in", 3600),
                            0  # 新用戶預設為未訂閱
                    ))
                
                if not use_postgresql:
                    conn.commit()
                conn.close()
                
                # 生成應用程式訪問令牌
                app_access_token = generate_access_token(user_id)
                
                # 使用 URL 編碼確保參數安全
                from urllib.parse import quote, unquote
                safe_token = quote(app_access_token)
                safe_user_id = quote(user_id)
                safe_email = quote(google_user.email or '')
                safe_name = quote(google_user.name or '')
                safe_picture = quote(google_user.picture or '')
                # 取回 state 中的前端 base（若在白名單內）
                frontend_base = FRONTEND_BASE_URL
                try:
                    if state:
                        decoded = unquote(state)
                        if decoded in ALLOWED_FRONTENDS:
                            frontend_base = decoded
                except Exception:
                    pass
                # 檢查 redirect_uri 是否為後台管理系統
                is_admin_system = False
                try:
                    if redirect_uri:
                        decoded_redirect = unquote(redirect_uri)
                        # 檢查是否包含 admin_login 參數或後台管理系統路徑
                        if 'admin_login=true' in decoded_redirect or '/admin' in decoded_redirect or 'manage-system' in decoded_redirect:
                            is_admin_system = True
                except Exception:
                    pass
                
                # 如果是後台管理系統，直接 redirect 到 redirect_uri 並帶上 token
                if is_admin_system and redirect_uri:
                    decoded_redirect = unquote(redirect_uri)
                    # 移除可能存在的參數，只保留基礎 URL
                    redirect_base = decoded_redirect.split('?')[0]
                    callback_url = (
                        f"{redirect_base}"
                        f"?token={safe_token}"
                        f"&user_id={safe_user_id}"
                        f"&email={safe_email}"
                        f"&name={safe_name}"
                        f"&picture={safe_picture}"
                    )
                else:
                    # 檢查是否為本地開發環境（localhost）
                    # 如果是本地環境，直接重定向到主頁並帶上 token 參數
                    # 如果是生產環境，使用 popup-callback.html（彈窗模式）
                    if 'localhost' in frontend_base or '127.0.0.1' in frontend_base:
                        # 本地開發：直接重定向到主頁
                        callback_url = (
                            f"{frontend_base}/"
                            f"?token={safe_token}"
                            f"&user_id={safe_user_id}"
                            f"&email={safe_email}"
                            f"&name={safe_name}"
                            f"&picture={safe_picture}"
                        )
                    else:
                        # 生產環境：Redirect 到前端的 popup-callback.html 頁面
                        # 該頁面會使用 postMessage 傳遞 token 給主視窗並自動關閉
                        callback_url = (
                            f"{frontend_base}/auth/popup-callback.html"
                            f"?token={safe_token}"
                            f"&user_id={safe_user_id}"
                            f"&email={safe_email}"
                            f"&name={safe_name}"
                            f"&picture={safe_picture}"
                        )
                
                print(f"DEBUG: Redirecting to callback URL: {callback_url}")
                
                # 設置適當的 HTTP Header 以支援 popup 通信
                response = RedirectResponse(url=callback_url)
                response.headers["Cross-Origin-Opener-Policy"] = "same-origin-allow-popups"
                return response
                
        except Exception as e:
            # 處理錯誤訊息以安全地嵌入 JavaScript（先處理再放入 f-string）
            error_msg = str(e).replace("'", "\\'").replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')
            
            # 返回錯誤頁面
            error_html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>登入失敗</title>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        height: 100vh;
                        margin: 0;
                        background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                    }}
                    .container {{
                        text-align: center;
                        background: white;
                        padding: 40px;
                        border-radius: 12px;
                        box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
                    }}
                    h2 {{ color: #e74c3c; margin: 0 0 10px 0; }}
                    p {{ color: #7f8c8d; margin: 0; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h2>❌ 登入失敗</h2>
                    <p>{error_msg}</p>
                </div>
                <script>
                    (function() {{
                        try {{
                    if (window.opener) {{
                        window.opener.postMessage({{
                            type: 'GOOGLE_AUTH_ERROR',
                                    error: '{error_msg}'
                        }}, '*');
                                setTimeout(function() {{
                                    try {{
                                        window.close();
                                    }} catch (closeErr) {{
                                        console.log('Unable to close window:', closeErr);
                                    }}
                                }}, 3000);
                            }}
                        }} catch (postErr) {{
                            console.error('Error sending error message:', postErr);
                        }}
                    }})();
                </script>
            </body>
            </html>
            """
            
            # 設置適當的 HTTP Header 以支援 popup 通信
            error_response = HTMLResponse(content=error_html, status_code=500)
            error_response.headers["Cross-Origin-Opener-Policy"] = "same-origin-allow-popups"
            error_response.headers["Access-Control-Allow-Origin"] = "https://aivideonew.zeabur.app"
            return error_response

    # ===== ECPay 金流串接 =====
    
    @app.post("/api/payment/checkout", response_class=HTMLResponse)
    async def create_payment_order(request: Request, current_user_id: Optional[str] = Depends(get_current_user)):
        """建立 ECPay 付款訂單並返回付款表單
        
        請求參數：
        - plan: 'monthly' | 'yearly'
        - amount: 金額（可選，會根據 plan 自動計算）
        - name: 姓名
        - email: 電子信箱
        - phone: 電話（可選）
        - invoiceType: 發票類型（可選）
        - vat: 統編（可選）
        - note: 備註（可選）
        """
        if not current_user_id:
            return HTMLResponse("<html><body><h1>請先登入</h1></body></html>", status_code=401)
        
        if not ECPAY_MERCHANT_ID or not ECPAY_HASH_KEY or not ECPAY_HASH_IV:
            return HTMLResponse("<html><body><h1>ECPay 設定未完成，請聯繫管理員</h1></body></html>", status_code=500)
        
        try:
            body = await request.json()
            plan = body.get("plan")
            amount = body.get("amount")
            name = body.get("name", "")
            email = body.get("email", "")
            phone = body.get("phone", "")
            invoice_type = body.get("invoiceType", "")
            vat = body.get("vat", "")
            note = body.get("note", "")
            
            # 驗證必填欄位
            if not plan or plan not in ("monthly", "yearly"):
                return HTMLResponse("<html><body><h1>無效的方案類型</h1></body></html>", status_code=400)
            
            if not name or not email:
                return HTMLResponse("<html><body><h1>請填寫姓名和電子信箱</h1></body></html>", status_code=400)
            
            # 計算金額（如果未提供）
            if not amount:
                amount = 1990 if plan == "monthly" else 19900  # 預設價格
            
            # 生成訂單號
            trade_no = f"RM{current_user_id[:8]}{int(time.time())}{uuid.uuid4().hex[:6].upper()}"
            
            # 建立訂單記錄（pending 狀態）
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            try:
                if use_postgresql:
                    cursor.execute("""
                        INSERT INTO orders (user_id, order_id, plan_type, amount, payment_status, payment_method, 
                                          invoice_type, vat_number, name, email, phone, note, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                    """, (current_user_id, trade_no, plan, amount, "pending", "ecpay", 
                          invoice_type or None, vat or None, name or None, email or None, phone or None, note or None))
                else:
                    cursor.execute("""
                        INSERT INTO orders (user_id, order_id, plan_type, amount, payment_status, payment_method, 
                                          invoice_type, vat_number, name, email, phone, note, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """, (current_user_id, trade_no, plan, amount, "pending", "ecpay", 
                          invoice_type or None, vat or None, name or None, email or None, phone or None, note or None))
                
                conn.commit()
            except Exception as e:
                print(f"WARN: 建立訂單記錄失敗: {e}")
                conn.rollback()
            finally:
                cursor.close()
                conn.close()
            
            # 準備 ECPay 參數
            trade_date = get_taiwan_time().strftime("%Y/%m/%d %H:%M:%S")
            item_name = f"ReelMind {'月費' if plan == 'monthly' else '年費'}方案"
            
            ecpay_data = {
                "MerchantID": ECPAY_MERCHANT_ID,
                "MerchantTradeNo": trade_no,
                "MerchantTradeDate": trade_date,
                "PaymentType": "aio",
                "TotalAmount": int(amount),
                "TradeDesc": item_name,
                "ItemName": item_name,
                "ReturnURL": ECPAY_NOTIFY_URL,  # 伺服器端通知
                "OrderResultURL": f"{ECPAY_RETURN_URL}?order_id={trade_no}",  # 用戶返回頁
                "ChoosePayment": "ALL",  # 讓用戶自行選擇付款方式（信用卡、LINE Pay、Apple Pay、ATM、超商等）
                "EncryptType": 1,
                "ClientBackURL": ECPAY_RETURN_URL,  # 取消付款返回頁
            }
            
            # 生成簽章
            ecpay_data["CheckMacValue"] = gen_check_mac_value(ecpay_data)
            
            # 生成 HTML 表單（自動提交到 ECPay）
            inputs = "\n".join([f'<input type="hidden" name="{k}" value="{v}"/>' for k, v in ecpay_data.items()])
            html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>正在導向至付款頁面...</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }}
        .container {{
            text-align: center;
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
        }}
        .spinner {{
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }}
        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <h2>正在導向至付款頁面...</h2>
        <div class="spinner"></div>
        <p>請稍候，即將為您跳轉</p>
    </div>
    <form id="ecpayForm" method="post" action="{ECPAY_API}">
        {inputs}
    </form>
    <script>
        document.getElementById("ecpayForm").submit();
    </script>
</body>
</html>'''
            
            return HTMLResponse(html)
        
        except Exception as e:
            print(f"ERROR: 建立付款訂單失敗: {e}")
            return HTMLResponse(f"<html><body><h1>建立訂單失敗: {str(e)}</h1></body></html>", status_code=500)
    
    @app.post("/api/payment/webhook", response_class=PlainTextResponse)
    async def ecpay_webhook(request: Request):
        """ECPay 伺服器端通知（Webhook）
        
        這是 ECPay 主動通知的端點，用於更新訂單狀態。
        必須驗證簽章和 IP 白名單。
        """
        try:
            # 獲取表單數據
            form = await request.form()
            params = dict(form.items())
            
            # 驗證 IP 白名單（完整實作）
            client_ip = request.client.host if request.client else None
            # 獲取真實 IP（考慮反向代理）
            if "x-forwarded-for" in request.headers:
                client_ip = request.headers["x-forwarded-for"].split(",")[0].strip()
            
            if not is_ecpay_ip(client_ip):
                logger.warning(f"非 ECPay IP 嘗試訪問 webhook: {client_ip}")
                # 生產環境應該返回錯誤
                if os.getenv("ENVIRONMENT", "production") == "production":
                    return PlainTextResponse("0|FAIL")
            
            # 驗證簽章
            if not verify_ecpay_signature(params):
                print("ERROR: ECPay Webhook 簽章驗證失敗")
                return PlainTextResponse("0|FAIL")
            
            # 獲取訂單資訊
            merchant_trade_no = params.get("MerchantTradeNo", "")  # 我方訂單號
            trade_no = params.get("TradeNo", "")  # 綠界交易號
            rtn_code = params.get("RtnCode", "")
            payment_date = params.get("PaymentDate", "")
            trade_amt = params.get("TradeAmt", "")
            payment_type = params.get("PaymentType", "")  # 付款方式（Credit, ATM, CVS, etc.）
            
            # 儲存原始回呼內容（用於稽核）
            raw_payload_json = json.dumps(params, ensure_ascii=False)
            
            # 獲取 ATM/超商相關資訊
            expire_date = params.get("ExpireDate", "")  # ATM/超商取號有效期限
            payment_code = params.get("PaymentNo", "") or params.get("Barcode1", "") or params.get("Barcode2", "") or params.get("Barcode3", "")  # CVS 代碼 / ATM 虛擬帳號
            bank_code = params.get("BankCode", "")  # ATM 銀行代碼
            
            # 記錄回呼資訊
            logger.info(f"ECPay Webhook 回呼: merchant_trade_no={merchant_trade_no}, trade_no={trade_no}, rtn_code={rtn_code}, payment_type={payment_type}")
            
            # 檢查付款狀態
            if str(rtn_code) != "1":
                logger.warning(f"ECPay 付款失敗，訂單號: {merchant_trade_no}, RtnCode: {rtn_code}")
                # 仍然更新訂單狀態為 failed，並儲存原始資料
                try:
                    conn = get_db_connection()
                    cursor = conn.cursor()
                    database_url = os.getenv("DATABASE_URL")
                    use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
                    
                    if use_postgresql:
                        cursor.execute("""
                            UPDATE orders 
                            SET payment_status = %s, 
                                raw_payload = %s,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE order_id = %s
                        """, ("failed", raw_payload_json, merchant_trade_no))
                    else:
                        cursor.execute("""
                            UPDATE orders 
                            SET payment_status = ?, 
                                raw_payload = ?,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE order_id = ?
                        """, ("failed", raw_payload_json, merchant_trade_no))
                    
                    conn.commit()
                    cursor.close()
                    conn.close()
                except Exception as e:
                    logger.error(f"更新失敗訂單狀態時出錯: {e}")
                
                return PlainTextResponse("1|OK")  # 仍然返回 OK，避免 ECPay 重複通知
            
            # 更新訂單狀態
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            try:
                # 查詢訂單（使用 merchant_trade_no，因為這是我們建立的訂單號）
                if use_postgresql:
                    cursor.execute(
                        "SELECT user_id, plan_type, amount, payment_status, trade_no FROM orders WHERE order_id = %s",
                        (merchant_trade_no,)
                    )
                else:
                    cursor.execute(
                        "SELECT user_id, plan_type, amount, payment_status, trade_no FROM orders WHERE order_id = ?",
                        (merchant_trade_no,)
                    )
                
                order = cursor.fetchone()
                
                if not order:
                    logger.warning(f"找不到訂單: {merchant_trade_no}")
                    return PlainTextResponse("1|OK")
                
                user_id, plan_type, amount, current_status, existing_trade_no = order
                
                # 冪等處理：檢查是否已經處理過（使用 merchant_trade_no + trade_no）
                if existing_trade_no and existing_trade_no == trade_no and current_status == "paid":
                    logger.info(f"訂單已處理過: {merchant_trade_no}, trade_no: {trade_no}")
                    return PlainTextResponse("1|OK")
                
                # 判斷付款方式類型
                is_atm_cvs = payment_type in ("ATM", "CVS", "BARCODE")
                is_credit_linepay = payment_type in ("Credit", "WebATM") or "LINE" in payment_type.upper() or "APPLE" in payment_type.upper()
                
                # 處理 ATM/超商取號（第一次回調）
                if is_atm_cvs and current_status == "pending":
                    # 這是取號成功的回調，尚未付款
                    expire_datetime = None
                    if expire_date:
                        try:
                            # ECPay 的日期格式通常是 "YYYY/MM/DD HH:mm:ss"
                            expire_datetime = datetime.strptime(expire_date, "%Y/%m/%d %H:%M:%S")
                        except:
                            try:
                                expire_datetime = datetime.strptime(expire_date, "%Y/%m/%d")
                            except:
                                logger.warning(f"無法解析有效期限: {expire_date}")
                    
                    # 更新訂單：儲存取號資訊，狀態仍為 pending
                    if use_postgresql:
                        cursor.execute("""
                            UPDATE orders 
                            SET trade_no = %s,
                                payment_method = %s,
                                payment_code = %s,
                                bank_code = %s,
                                expire_date = %s,
                                raw_payload = %s,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE order_id = %s
                        """, (trade_no, payment_type, payment_code or None, bank_code or None, expire_datetime, raw_payload_json, merchant_trade_no))
                    else:
                        cursor.execute("""
                            UPDATE orders 
                            SET trade_no = ?,
                                payment_method = ?,
                                payment_code = ?,
                                bank_code = ?,
                                expire_date = ?,
                                raw_payload = ?,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE order_id = ?
                        """, (trade_no, payment_type, payment_code or None, bank_code or None, expire_datetime, raw_payload_json, merchant_trade_no))
                    
                    conn.commit()
                    logger.info(f"ATM/超商取號成功，訂單號: {merchant_trade_no}, 付款代碼: {payment_code}")
                    return PlainTextResponse("1|OK")
                
                # 處理信用卡/LINE Pay/Apple Pay 或 ATM/超商付款完成
                if is_credit_linepay or (is_atm_cvs and current_status == "pending" and rtn_code == "1"):
                    # 這是付款完成的回調
                    
                    # 計算到期日
                    days = 30 if plan_type == "monthly" else 365
                    expires_dt = get_taiwan_time() + timedelta(days=days)
                    
                    # 查詢訂單發票資訊
                    if use_postgresql:
                        cursor.execute(
                            "SELECT invoice_type, vat_number FROM orders WHERE order_id = %s",
                            (merchant_trade_no,)
                        )
                    else:
                        cursor.execute(
                            "SELECT invoice_type, vat_number FROM orders WHERE order_id = ?",
                            (merchant_trade_no,)
                        )
                    
                    invoice_info = cursor.fetchone()
                    invoice_type = invoice_info[0] if invoice_info and invoice_info[0] else None
                    vat_number = invoice_info[1] if invoice_info and invoice_info[1] else None
                    
                    # 開立發票（如果啟用）
                    invoice_number = None
                    if ECPAY_INVOICE_ENABLED and invoice_type:
                        try:
                            invoice_number = await issue_ecpay_invoice(
                                trade_no=merchant_trade_no,
                                amount=int(trade_amt),
                                invoice_type=invoice_type,
                                vat_number=vat_number,
                                user_id=user_id
                            )
                            if invoice_number:
                                logger.info(f"發票開立成功，訂單號: {merchant_trade_no}, 發票號: {invoice_number}")
                            else:
                                logger.warning(f"發票開立失敗，訂單號: {merchant_trade_no}")
                        except Exception as e:
                            logger.error(f"發票開立異常，訂單號: {merchant_trade_no}, 錯誤: {e}")
                    
                    # 解析付款時間
                    paid_at_datetime = None
                    if payment_date:
                        try:
                            paid_at_datetime = datetime.strptime(payment_date, "%Y/%m/%d %H:%M:%S")
                        except:
                            try:
                                paid_at_datetime = datetime.strptime(payment_date, "%Y/%m/%d")
                            except:
                                paid_at_datetime = get_taiwan_time()
                    else:
                        paid_at_datetime = get_taiwan_time()
                    
                    # 更新訂單狀態為已付款
                    if use_postgresql:
                        cursor.execute("""
                            UPDATE orders 
                            SET payment_status = %s, 
                                payment_method = %s,
                                trade_no = %s,
                                paid_at = %s, 
                                expires_at = %s,
                                invoice_number = %s,
                                raw_payload = %s,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE order_id = %s
                        """, ("paid", payment_type, trade_no, paid_at_datetime, expires_dt, invoice_number or merchant_trade_no, raw_payload_json, merchant_trade_no))
                    else:
                        cursor.execute("""
                            UPDATE orders 
                            SET payment_status = ?, 
                                payment_method = ?,
                                trade_no = ?,
                                paid_at = ?, 
                                expires_at = ?,
                                invoice_number = ?,
                                raw_payload = ?,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE order_id = ?
                        """, ("paid", payment_type, trade_no, paid_at_datetime, expires_dt, invoice_number or merchant_trade_no, raw_payload_json, merchant_trade_no))
                    
                    # 更新/建立 licenses 記錄（只在付款完成時）
                    if use_postgresql:
                        cursor.execute("""
                            INSERT INTO licenses (user_id, tier, seats, expires_at, status, updated_at)
                            VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                            ON CONFLICT (user_id)
                            DO UPDATE SET
                                tier = EXCLUDED.tier,
                                expires_at = EXCLUDED.expires_at,
                                status = EXCLUDED.status,
                                updated_at = CURRENT_TIMESTAMP
                        """, (user_id, plan_type, 1, expires_dt, "active"))
                    else:
                        cursor.execute("""
                            INSERT OR REPLACE INTO licenses
                            (user_id, tier, seats, expires_at, status, updated_at)
                            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                        """, (user_id, plan_type, 1, expires_dt.timestamp(), "active"))
                    
                    # 更新用戶訂閱狀態
                    if use_postgresql:
                        cursor.execute(
                            "UPDATE user_auth SET is_subscribed = 1, updated_at = CURRENT_TIMESTAMP WHERE user_id = %s",
                            (user_id,)
                        )
                    else:
                        cursor.execute(
                            "UPDATE user_auth SET is_subscribed = 1, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
                            (user_id,)
                        )
                    
                    conn.commit()
                    logger.info(f"訂單付款完成，訂單號: {merchant_trade_no}, 付款方式: {payment_type}")
                    return PlainTextResponse("1|OK")
                
                # 如果不符合上述條件，記錄警告
                logger.warning(f"未處理的付款回調，訂單號: {merchant_trade_no}, payment_type: {payment_type}, current_status: {current_status}, rtn_code: {rtn_code}")
                conn.commit()
                return PlainTextResponse("1|OK")
                
            except Exception as e:
                print(f"ERROR: 更新訂單狀態失敗: {e}")
                conn.rollback()
                return PlainTextResponse("0|FAIL")
            finally:
                cursor.close()
                conn.close()
            
            return PlainTextResponse("1|OK")
        
        except Exception as e:
            print(f"ERROR: ECPay Webhook 處理失敗: {e}")
            return PlainTextResponse("0|FAIL")
    
    @app.get("/api/payment/return")
    async def ecpay_return(request: Request):
        """ECPay 用戶返回頁（用戶瀏覽器返回）
        
        用戶完成付款後，ECPay 會 redirect 到這個頁面。
        驗證簽章後，redirect 到前端結果頁。
        """
        try:
            # 獲取 URL 參數
            params = dict(request.query_params.items())
            
            # 驗證簽章
            if not verify_ecpay_signature(params):
                print("ERROR: ECPay Return 簽章驗證失敗")
                return RedirectResponse(
                    url=f"{ECPAY_RETURN_URL}?status=error&message=簽章驗證失敗",
                    status_code=302
                )
            
            # 獲取訂單資訊
            merchant_trade_no = params.get("MerchantTradeNo", "")
            rtn_code = params.get("RtnCode", "")
            payment_type = params.get("PaymentType", "")
            
            # 查詢訂單狀態
            conn = get_db_connection()
            cursor = conn.cursor()
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            try:
                if use_postgresql:
                    cursor.execute(
                        "SELECT payment_status FROM orders WHERE order_id = %s",
                        (merchant_trade_no,)
                    )
                else:
                    cursor.execute(
                        "SELECT payment_status FROM orders WHERE order_id = ?",
                        (merchant_trade_no,)
                    )
                
                order = cursor.fetchone()
                order_status = order[0] if order else None
                
                cursor.close()
                conn.close()
            except Exception as e:
                logger.error(f"查詢訂單狀態失敗: {e}")
                order_status = None
            
            # 判斷付款方式類型
            is_atm_cvs = payment_type in ("ATM", "CVS", "BARCODE")
            
            # 檢查付款狀態
            if str(rtn_code) == "1":
                # 付款成功，redirect 到前端成功頁
                return RedirectResponse(
                    url=f"{ECPAY_RETURN_URL}?status=success&order_id={merchant_trade_no}",
                    status_code=302
                )
            elif is_atm_cvs and order_status == "pending":
                # ATM/超商取號成功，但尚未付款
                return RedirectResponse(
                    url=f"{ECPAY_RETURN_URL}?status=pending&order_id={merchant_trade_no}",
                    status_code=302
                )
            else:
                # 付款失敗，redirect 到前端失敗頁
                rtn_msg = params.get("RtnMsg", "付款失敗")
                return RedirectResponse(
                    url=f"{ECPAY_RETURN_URL}?status=failed&order_id={merchant_trade_no}&message={urllib.parse.quote(rtn_msg)}",
                    status_code=302
                )
        
        except Exception as e:
            print(f"ERROR: ECPay Return 處理失敗: {e}")
            return RedirectResponse(
                url=f"{ECPAY_RETURN_URL}?status=error&message=處理失敗",
                status_code=302
            )
    
    # ===== 多通路授權整合 API =====
    
    @app.post("/api/webhook/verify-license")
    async def verify_license_webhook(request: Request):
        """接收 n8n/Portaly/PPA 的授權通知，產生授權連結
        
        這個端點由 n8n 調用，用於建立授權記錄並生成授權連結。
        
        請求參數：
        - channel: 通路名稱（例如：portaly, ppa, n8n）
        - order_id: 通路訂單號
        - email: 用戶 Email
        - plan_type: 方案類型（monthly/yearly），預設為 yearly（1年）
        - amount: 金額（可選）
        - product_name: 產品名稱（可選）
        
        返回：
        - activation_token: 授權 token
        - activation_link: 授權連結（可直接寄送給用戶）
        - expires_at: 授權到期時間
        """
        try:
            body = await request.json()
            channel = body.get("channel", "n8n")  # 預設為 n8n
            order_id = body.get("order_id")
            email = body.get("email")
            plan_type = body.get("plan_type", "yearly")  # 預設為 1 年
            amount = body.get("amount", 0)
            product_name = body.get("product_name", "")
            
            # 驗證必填欄位
            if not order_id or not email:
                return JSONResponse({"error": "缺少必填欄位：order_id 和 email"}, status_code=400)
            
            # 判斷方案類型（如果未提供，從 product_name 或 amount 判斷）
            if plan_type not in ("monthly", "yearly"):
                if "年" in product_name or amount >= 19900:
                    plan_type = "yearly"
                else:
                    plan_type = "yearly"  # 預設為 1 年
            
            # 生成授權 token
            activation_token = secrets.token_urlsafe(32)
            
            # 計算授權到期日（1 年 = 365 天）
            days = 30 if plan_type == "monthly" else 365
            license_expires_at = get_taiwan_time() + timedelta(days=days)
            
            # 授權連結有效期限（7 天內有效）
            link_expires_at = get_taiwan_time() + timedelta(days=7)
            
            # 儲存授權記錄
            conn = get_db_connection()
            cursor = conn.cursor()
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            try:
                if use_postgresql:
                    cursor.execute("""
                        INSERT INTO license_activations 
                        (activation_token, channel, order_id, email, plan_type, amount, 
                         link_expires_at, license_expires_at, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                    """, (activation_token, channel, order_id, email, plan_type, amount, 
                          link_expires_at, license_expires_at))
                else:
                    cursor.execute("""
                        INSERT INTO license_activations 
                        (activation_token, channel, order_id, email, plan_type, amount, 
                         link_expires_at, license_expires_at, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """, (activation_token, channel, order_id, email, plan_type, amount, 
                          link_expires_at.timestamp(), license_expires_at.timestamp()))
                
                if not use_postgresql:
                    conn.commit()
                cursor.close()
                conn.close()
            except Exception as e:
                logger.error(f"儲存授權記錄失敗: {e}", exc_info=True)
                if not use_postgresql:
                    conn.rollback()
                conn.close()
                return JSONResponse({"error": "儲存授權記錄失敗"}, status_code=500)
            
            # 生成授權連結
            frontend_url = os.getenv("FRONTEND_URL", "https://aivideonew.zeabur.app")
            activation_link = f"{frontend_url}/activate?token={activation_token}"
            
            logger.info(f"授權記錄建立成功: channel={channel}, order_id={order_id}, email={email}, plan_type={plan_type}")
            
            return {
                "status": "success",
                "activation_token": activation_token,
                "activation_link": activation_link,
                "plan_type": plan_type,
                "license_expires_at": license_expires_at.isoformat(),
                "link_expires_at": link_expires_at.isoformat(),
                "message": "授權連結已生成，請將 activation_link 寄送給用戶"
            }
            
        except Exception as e:
            logger.error(f"處理授權 Webhook 失敗: {e}", exc_info=True)
            return JSONResponse({"error": f"處理失敗: {str(e)}"}, status_code=500)
    
    @app.get("/api/user/license/verify")
    async def verify_license_token(
        token: str,
        current_user_id: Optional[str] = Depends(get_current_user)
    ):
        """驗證授權連結並啟用訂閱
        
        用戶點擊授權連結時，這個端點會：
        1. 驗證授權 token
        2. 檢查是否已使用或過期
        3. 如果用戶未登入，導向登入頁
        4. 如果用戶已登入，啟用訂閱並更新 licenses 表
        """
        if not token:
            return JSONResponse({"error": "缺少授權 token"}, status_code=400)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        database_url = os.getenv("DATABASE_URL")
        use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
        
        try:
            # 查詢授權記錄
            if use_postgresql:
                cursor.execute("""
                    SELECT id, channel, order_id, email, plan_type, amount, status, 
                           link_expires_at, license_expires_at, activated_at, activated_by_user_id
                    FROM license_activations 
                    WHERE activation_token = %s
                """, (token,))
            else:
                cursor.execute("""
                    SELECT id, channel, order_id, email, plan_type, amount, status, 
                           link_expires_at, license_expires_at, activated_at, activated_by_user_id
                    FROM license_activations 
                    WHERE activation_token = ?
                """, (token,))
            
            activation = cursor.fetchone()
            
            if not activation:
                return JSONResponse({"error": "無效的授權連結"}, status_code=404)
            
            activation_id, channel, order_id, email, plan_type, amount, status, link_expires_at, license_expires_at, activated_at, activated_by_user_id = activation
            
            # 檢查是否已啟用
            if status == "activated":
                return JSONResponse({"error": "此授權連結已使用"}, status_code=400)
            
            # 檢查連結是否過期
            if link_expires_at:
                if use_postgresql:
                    expire_dt = link_expires_at
                else:
                    expire_dt = datetime.fromtimestamp(link_expires_at)
                
                if expire_dt < get_taiwan_time():
                    # 更新狀態為過期
                    if use_postgresql:
                        cursor.execute(
                            "UPDATE license_activations SET status = 'expired' WHERE id = %s",
                            (activation_id,)
                        )
                    else:
                        cursor.execute(
                            "UPDATE license_activations SET status = 'expired' WHERE id = ?",
                            (activation_id,)
                        )
                    if not use_postgresql:
                        conn.commit()
                    return JSONResponse({"error": "授權連結已過期"}, status_code=400)
            
            # 如果用戶未登入，導向登入頁（帶上 token）
            if not current_user_id:
                frontend_url = os.getenv("FRONTEND_URL", "https://aivideonew.zeabur.app")
                return RedirectResponse(
                    url=f"{frontend_url}/#login?activation_token={token}",
                    status_code=302
                )
            
            # 獲取授權到期日
            if use_postgresql:
                license_expire_dt = license_expires_at
            else:
                license_expire_dt = datetime.fromtimestamp(license_expires_at) if license_expires_at else None
            
            if not license_expire_dt:
                # 如果沒有設定到期日，計算 1 年
                days = 30 if plan_type == "monthly" else 365
                license_expire_dt = get_taiwan_time() + timedelta(days=days)
            
            # 更新授權記錄為已啟用
            if use_postgresql:
                cursor.execute("""
                    UPDATE license_activations 
                    SET status = 'activated',
                        activated_at = CURRENT_TIMESTAMP,
                        activated_by_user_id = %s
                    WHERE id = %s
                """, (current_user_id, activation_id))
            else:
                cursor.execute("""
                    UPDATE license_activations 
                    SET status = 'activated',
                        activated_at = CURRENT_TIMESTAMP,
                        activated_by_user_id = ?
                    WHERE id = ?
                """, (current_user_id, activation_id))
            
            # 建立/更新 licenses 記錄
            if use_postgresql:
                cursor.execute("""
                    INSERT INTO licenses (user_id, tier, seats, expires_at, status, source, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                    ON CONFLICT (user_id)
                    DO UPDATE SET
                        tier = EXCLUDED.tier,
                        expires_at = EXCLUDED.expires_at,
                        status = EXCLUDED.status,
                        source = EXCLUDED.source,
                        updated_at = CURRENT_TIMESTAMP
                """, (current_user_id, plan_type, 1, license_expire_dt, "active", channel))
            else:
                cursor.execute("""
                    INSERT OR REPLACE INTO licenses
                    (user_id, tier, seats, expires_at, status, source, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, (current_user_id, plan_type, 1, license_expire_dt.timestamp(), "active", channel))
            
            # 更新用戶訂閱狀態
            if use_postgresql:
                cursor.execute(
                    "UPDATE user_auth SET is_subscribed = 1, updated_at = CURRENT_TIMESTAMP WHERE user_id = %s",
                    (current_user_id,)
                )
            else:
                cursor.execute(
                    "UPDATE user_auth SET is_subscribed = 1, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
                    (current_user_id,)
                )
            
            if not use_postgresql:
                conn.commit()
            cursor.close()
            conn.close()
            
            logger.info(f"授權啟用成功: activation_id={activation_id}, user_id={current_user_id}, plan_type={plan_type}, expires_at={license_expire_dt}")
            
            # Redirect 到前端成功頁
            frontend_url = os.getenv("FRONTEND_URL", "https://aivideonew.zeabur.app")
            return RedirectResponse(
                url=f"{frontend_url}/?activation=success&plan={plan_type}",
                status_code=302
            )
            
        except Exception as e:
            logger.error(f"驗證授權連結失敗: {e}", exc_info=True)
            if not use_postgresql:
                conn.rollback()
            conn.close()
            return JSONResponse({"error": f"驗證失敗: {str(e)}"}, status_code=500)
    
    @app.delete("/api/admin/license-activations/{activation_id}")
    async def delete_license_activation(
        activation_id: int,
        admin_user: str = Depends(get_admin_user)
    ):
        """刪除授權啟用記錄（管理員專用）
        
        用於刪除測試資料或錯誤的授權記錄。
        """
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            # 先查詢記錄是否存在
            if use_postgresql:
                cursor.execute(
                    "SELECT id, order_id, email, status FROM license_activations WHERE id = %s",
                    (activation_id,)
                )
            else:
                cursor.execute(
                    "SELECT id, order_id, email, status FROM license_activations WHERE id = ?",
                    (activation_id,)
                )
            
            record = cursor.fetchone()
            
            if not record:
                return JSONResponse({"error": "找不到指定的授權記錄"}, status_code=404)
            
            order_id, email, status = record[1], record[2], record[3]
            
            # 刪除記錄
            if use_postgresql:
                cursor.execute(
                    "DELETE FROM license_activations WHERE id = %s",
                    (activation_id,)
                )
            else:
                cursor.execute(
                    "DELETE FROM license_activations WHERE id = ?",
                    (activation_id,)
                )
            
            if not use_postgresql:
                conn.commit()
            cursor.close()
            conn.close()
            
            logger.info(f"管理員刪除授權記錄: activation_id={activation_id}, order_id={order_id}, email={email}, status={status}")
            
            return {
                "message": "授權記錄已刪除",
                "activation_id": activation_id,
                "order_id": order_id,
                "email": email
            }
            
        except Exception as e:
            logger.error(f"刪除授權記錄失敗: {e}", exc_info=True)
            if not use_postgresql:
                conn.rollback()
            conn.close()
            return JSONResponse({"error": f"刪除失敗: {str(e)}"}, status_code=500)
    
    @app.get("/api/admin/license-activations")
    async def list_license_activations(
        status: Optional[str] = None,
        channel: Optional[str] = None,
        limit: int = 100,
        admin_user: str = Depends(get_admin_user)
    ):
        """列出所有授權啟用記錄（管理員專用）
        
        用於查看和管理授權記錄，包括測試資料。
        
        查詢參數：
        - status: 篩選狀態（pending/activated/expired）
        - channel: 篩選通路（n8n/portaly/ppa）
        - limit: 限制筆數（預設 100）
        """
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            # 建立查詢
            query = "SELECT id, activation_token, channel, order_id, email, plan_type, amount, status, activated_at, link_expires_at, license_expires_at, created_at FROM license_activations WHERE 1=1"
            params = []
            
            if status:
                if use_postgresql:
                    query += " AND status = %s"
                else:
                    query += " AND status = ?"
                params.append(status)
            
            if channel:
                if use_postgresql:
                    query += " AND channel = %s"
                else:
                    query += " AND channel = ?"
                params.append(channel)
            
            query += " ORDER BY created_at DESC"
            
            if use_postgresql:
                query += f" LIMIT {limit}"
            else:
                query += f" LIMIT ?"
                params.append(limit)
            
            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()
            conn.close()
            
            activations = []
            for row in rows:
                activations.append({
                    "id": row[0],
                    "activation_token": row[1][:20] + "..." if row[1] and len(row[1]) > 20 else row[1],  # 只顯示前20字元
                    "channel": row[2],
                    "order_id": row[3],
                    "email": row[4],
                    "plan_type": row[5],
                    "amount": row[6],
                    "status": row[7],
                    "activated_at": str(row[8]) if row[8] else None,
                    "link_expires_at": str(row[9]) if row[9] else None,
                    "license_expires_at": str(row[10]) if row[10] else None,
                    "created_at": str(row[11]) if row[11] else None
                })
            
            return {
                "activations": activations,
                "total": len(activations)
            }
            
        except Exception as e:
            logger.error(f"查詢授權記錄失敗: {e}", exc_info=True)
            return JSONResponse({"error": f"查詢失敗: {str(e)}"}, status_code=500)
    
    @app.post("/api/payment/refund")
    async def refund_order(
        request: Request,
        admin_user: str = Depends(get_admin_user)
    ):
        """退款處理（管理員專用）
        
        請求參數：
        - order_id: 訂單號
        - refund_amount: 退款金額（可選，不填則全額退款）
        - refund_reason: 退款原因（可選）
        """
        try:
            body = await request.json()
            order_id = body.get("order_id")
            refund_amount = body.get("refund_amount")
            refund_reason = body.get("refund_reason", "管理員退款")
            
            if not order_id:
                return JSONResponse({"error": "缺少訂單號"}, status_code=400)
            
            # 處理退款
            result = await process_ecpay_refund(
                trade_no=order_id,
                refund_amount=refund_amount,
                refund_reason=refund_reason
            )
            
            if result.get("success"):
                return JSONResponse({
                    "message": "退款成功",
                    "order_id": order_id,
                    "refund_amount": result.get("refund_amount")
                })
            else:
                return JSONResponse({
                    "error": result.get("error", "退款失敗")
                }, status_code=400)
        
        except Exception as e:
            logger.error(f"退款處理失敗: {e}", exc_info=True)
            return JSONResponse({"error": "服務器錯誤，請稍後再試"}, status_code=500)
    
    # ===== 舊的金流回調（保留向後兼容，建議移除） =====
    @app.post("/api/payment/callback")
    async def payment_callback(payload: dict):
        """金流回調（測試/準備用）：更新用戶訂閱狀態與到期日。
        期待參數：
        - user_id: str
        - plan: 'monthly' | 'yearly'
        - transaction_id, amount, paid_at（可選，用於記錄）
        注意：正式上線需加入簽章驗證與來源白名單。
        """
        try:
            user_id = payload.get("user_id")
            plan = payload.get("plan")
            paid_at = payload.get("paid_at")
            transaction_id = payload.get("transaction_id")
            amount = payload.get("amount")

            if not user_id or plan not in ("monthly", "yearly"):
                raise HTTPException(status_code=400, detail="missing user_id or invalid plan")

            # 計算到期日
            days = 30 if plan == "monthly" else 365
            expires_dt = get_taiwan_time() + timedelta(days=days)

            conn = get_db_connection()
            cursor = conn.cursor()

            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE

            # 更新/建立 licenses 記錄，並設為 active
            if use_postgresql:
                try:
                    cursor.execute(
                        """
                        INSERT INTO licenses (user_id, tier, seats, expires_at, status, updated_at)
                        VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                        ON CONFLICT (user_id)
                        DO UPDATE SET
                            tier = EXCLUDED.tier,
                            expires_at = EXCLUDED.expires_at,
                            status = EXCLUDED.status,
                            updated_at = CURRENT_TIMESTAMP
                        """,
                        (user_id, plan, 1, expires_dt, "active")
                    )
                except Exception as e:
                    # 若 licenses 不存在，忽略而不阻擋主流程
                    print("WARN: update licenses failed:", e)
            else:
                try:
                    cursor.execute(
                        """
                        INSERT OR REPLACE INTO licenses
                        (user_id, tier, seats, expires_at, status, updated_at)
                        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                        """,
                        (user_id, plan, 1, expires_dt.timestamp(), "active")
                    )
                except Exception as e:
                    print("WARN: update licenses failed:", e)

            # 將 user 設為已訂閱
            if use_postgresql:
                cursor.execute(
                    "UPDATE user_auth SET is_subscribed = 1, updated_at = CURRENT_TIMESTAMP WHERE user_id = %s",
                    (user_id,)
                )
            else:
                cursor.execute(
                    "UPDATE user_auth SET is_subscribed = 1, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
                    (user_id,)
                )

            # 可選：記錄訂單（若有 orders 表）
            try:
                # 生成 order_id（如果 transaction_id 為空）
                order_id = transaction_id
                if not order_id:
                    # 生成唯一的 order_id：ORDER-{user_id前8位}-{timestamp}-{uuid前6位}
                    order_id = f"ORDER-{user_id[:8]}-{int(time.time())}-{uuid.uuid4().hex[:6].upper()}"
                
                if use_postgresql:
                    cursor.execute(
                        """
                        INSERT INTO orders (user_id, order_id, plan_type, amount, payment_status, paid_at, invoice_number, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                        """,
                        (user_id, order_id, plan, amount, "paid", paid_at, transaction_id)
                    )
                else:
                    cursor.execute(
                        """
                        INSERT INTO orders (user_id, order_id, plan_type, amount, payment_status, paid_at, invoice_number, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                        """,
                        (user_id, order_id, plan, amount, "paid", paid_at, transaction_id)
                    )
            except Exception as e:
                print("WARN: insert orders failed:", e)

            if not use_postgresql:
                conn.commit()
            conn.close()

            return {"ok": True, "user_id": user_id, "plan": plan, "expires_at": expires_dt.isoformat()}
        except HTTPException:
            raise
        except Exception as e:
            print("payment_callback error:", e)
            raise HTTPException(status_code=500, detail="payment callback failed")

    @app.post("/api/auth/google/callback")
    async def google_callback_post(request: dict):
        """處理 Google OAuth 回調（POST 請求 - 來自前端 JavaScript）"""
        try:
            # 從請求體獲取授權碼
            code = request.get("code")
            if not code:
                raise HTTPException(status_code=400, detail="Missing authorization code")
            
            # 交換授權碼獲取訪問令牌
            async with httpx.AsyncClient() as client:
                token_response = await client.post(
                    "https://oauth2.googleapis.com/token",
                    data={
                        "client_id": GOOGLE_CLIENT_ID,
                        "client_secret": GOOGLE_CLIENT_SECRET,
                        "code": code,
                        "grant_type": "authorization_code",
                        "redirect_uri": GOOGLE_REDIRECT_URI,
                    }
                )
                
                if token_response.status_code != 200:
                    raise HTTPException(status_code=400, detail="Failed to get access token")
                
                token_data = token_response.json()
                access_token = token_data["access_token"]
                
                # 獲取用戶資訊
                google_user = await get_google_user_info(access_token)
                if not google_user:
                    raise HTTPException(status_code=400, detail="Failed to get user info")
                
                # 生成用戶 ID
                user_id = generate_user_id(google_user.email)
                
                # 保存或更新用戶認證資訊
                conn = get_db_connection()
                cursor = conn.cursor()
                
                database_url = os.getenv("DATABASE_URL")
                use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
                
                if use_postgresql:
                    # PostgreSQL 語法
                    from datetime import timedelta
                    expires_at_value = get_taiwan_time() + timedelta(seconds=token_data.get("expires_in", 3600))
                    
                    cursor.execute("""
                        INSERT INTO user_auth 
                        (user_id, google_id, email, name, picture, access_token, expires_at, updated_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                        ON CONFLICT (user_id) 
                        DO UPDATE SET 
                            google_id = EXCLUDED.google_id,
                            email = EXCLUDED.email,
                            name = EXCLUDED.name,
                            picture = EXCLUDED.picture,
                            access_token = EXCLUDED.access_token,
                            expires_at = EXCLUDED.expires_at,
                            updated_at = CURRENT_TIMESTAMP
                    """, (
                        user_id,
                        google_user.id,
                        google_user.email,
                        google_user.name,
                        google_user.picture,
                        access_token,
                        expires_at_value
                    ))
                else:
                    # SQLite 語法
                    cursor.execute("""
                        INSERT OR REPLACE INTO user_auth 
                        (user_id, google_id, email, name, picture, access_token, expires_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """, (
                        user_id,
                        google_user.id,
                        google_user.email,
                        google_user.name,
                        google_user.picture,
                        access_token,
                        datetime.now().timestamp() + token_data.get("expires_in", 3600)
                    ))
                
                if not use_postgresql:
                    conn.commit()
                conn.close()
                
                # 生成應用程式訪問令牌
                app_access_token = generate_access_token(user_id)
                
                # 返回 JSON 格式（給前端 JavaScript 使用）
                return AuthToken(
                    access_token=app_access_token,
                    expires_in=86400,  # 24小時過期
                    user=google_user
                )
                
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/auth/refresh")
    async def refresh_token(
        current_user_id: Optional[str] = Depends(get_current_user_for_refresh)
    ):
        """刷新存取權杖（允許使用過期的 token）"""
        print(f"DEBUG: refresh_token - current_user_id={current_user_id}")
        if not current_user_id:
            print("DEBUG: refresh_token - current_user_id 為 None，返回 401")
            raise HTTPException(status_code=401, detail="未授權")
        print(f"DEBUG: refresh_token - 開始處理 refresh，user_id={current_user_id}")
        
        try:
            # 獲取資料庫連接
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            # 從資料庫獲取用戶的 refresh token（如果需要）
            # 但實際上我們直接生成新的 access token
            if use_postgresql:
                cursor.execute("SELECT user_id FROM user_auth WHERE user_id = %s", (current_user_id,))
            else:
                cursor.execute("SELECT user_id FROM user_auth WHERE user_id = ?", (current_user_id,))
            
            if not cursor.fetchone():
                conn.close()
                raise HTTPException(status_code=404, detail="用戶不存在")
            
            # 生成新的 access token
            new_access_token = generate_access_token(current_user_id)
            new_expires_at = get_taiwan_time() + timedelta(hours=24)
            
            # 更新資料庫中的 token
            if use_postgresql:
                cursor.execute("""
                    UPDATE user_auth 
                    SET access_token = %s, expires_at = %s, updated_at = CURRENT_TIMESTAMP
                    WHERE user_id = %s
                """, (new_access_token, new_expires_at, current_user_id))
            else:
                cursor.execute("""
                    UPDATE user_auth 
                    SET access_token = ?, expires_at = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE user_id = ?
                """, (new_access_token, new_expires_at.isoformat(), current_user_id))
                conn.commit()
            
            conn.close()
            
            return {
                "access_token": new_access_token,
                "expires_at": new_expires_at.isoformat()
            }
                
        except HTTPException:
            raise
        except Exception as e:
            print(f"刷新 token 錯誤: {e}")
            raise HTTPException(status_code=500, detail="內部伺服器錯誤")

    @app.get("/api/auth/me")
    async def get_current_user_info(current_user_id: Optional[str] = Depends(get_current_user)):
        """獲取當前用戶資訊"""
        if not current_user_id:
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            if use_postgresql:
                cursor.execute("""
                    SELECT google_id, email, name, picture, is_subscribed, created_at 
                    FROM user_auth 
                    WHERE user_id = %s
                """, (current_user_id,))
            else:
                cursor.execute("""
                    SELECT google_id, email, name, picture, is_subscribed, created_at 
                    FROM user_auth 
                    WHERE user_id = ?
                """, (current_user_id,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                # 格式化日期（台灣時區 UTC+8）
                created_at = row[5]
                if created_at:
                    try:
                        from datetime import timezone, timedelta
                        if isinstance(created_at, datetime):
                            # 如果是 datetime 對象，直接使用
                            dt = created_at
                        elif isinstance(created_at, str):
                            # 如果是字符串，解析它
                            dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                        else:
                            dt = None
                        
                        if dt:
                            # 轉換為台灣時區 (UTC+8)
                            taiwan_tz = timezone(timedelta(hours=8))
                            if dt.tzinfo is None:
                                # 如果沒有時區信息，假設是 UTC
                                dt = dt.replace(tzinfo=timezone.utc)
                            dt_taiwan = dt.astimezone(taiwan_tz)
                            created_at = dt_taiwan.strftime('%Y/%m/%d %H:%M')
                    except Exception as e:
                        print(f"格式化日期時出錯: {e}")
                        pass
                
                return {
                    "user_id": current_user_id,
                    "google_id": row[0],
                    "email": row[1],
                    "name": row[2],
                    "picture": row[3],
                    "is_subscribed": bool(row[4]) if row[4] is not None else True,  # 預設為已訂閱
                    "created_at": created_at
                }
            else:
                raise HTTPException(status_code=404, detail="User not found")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/auth/logout")
    async def logout(current_user_id: Optional[str] = Depends(get_current_user)):
        """登出用戶"""
        if not current_user_id:
            return {"message": "Already logged out"}
        
        # 這裡可以添加令牌黑名單邏輯
        return {"message": "Logged out successfully"}

    # ===== P0 功能：長期記憶＋個人化 =====
    
    @app.get("/api/profile/{user_id}")
    async def get_user_profile(user_id: str, current_user_id: Optional[str] = Depends(get_current_user)):
        """獲取用戶個人偏好"""
        if not current_user_id or current_user_id != user_id:
            return JSONResponse({"error": "無權限訪問此用戶資料"}, status_code=403)
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            if use_postgresql:
                cursor.execute("SELECT * FROM user_profiles WHERE user_id = %s", (user_id,))
            else:
                cursor.execute("SELECT * FROM user_profiles WHERE user_id = ?", (user_id,))
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {
                    "user_id": row[0],
                    "preferred_platform": row[1],
                    "preferred_style": row[2],
                    "preferred_duration": row[3],
                    "content_preferences": json.loads(row[4]) if row[4] else None,
                    "created_at": row[5],
                    "updated_at": row[6]
                }
            else:
                return {"message": "Profile not found", "user_id": user_id}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/profile")
    async def create_or_update_profile(profile: UserProfile, current_user_id: Optional[str] = Depends(get_current_user)):
        """創建或更新用戶個人偏好"""
        if not current_user_id or current_user_id != profile.user_id:
            return JSONResponse({"error": "無權限變更此用戶資料"}, status_code=403)
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            # 檢查是否已存在
            if use_postgresql:
                cursor.execute("SELECT user_id FROM user_profiles WHERE user_id = %s", (profile.user_id,))
            else:
                cursor.execute("SELECT user_id FROM user_profiles WHERE user_id = ?", (profile.user_id,))
            exists = cursor.fetchone()
            
            if exists:
                # 更新現有記錄
                if use_postgresql:
                    cursor.execute("""
                        UPDATE user_profiles 
                        SET preferred_platform = %s, preferred_style = %s, preferred_duration = %s, 
                            content_preferences = %s, updated_at = CURRENT_TIMESTAMP
                        WHERE user_id = %s
                    """, (
                        profile.preferred_platform,
                        profile.preferred_style,
                        profile.preferred_duration,
                        json.dumps(profile.content_preferences) if profile.content_preferences else None,
                        profile.user_id
                    ))
                else:
                    cursor.execute("""
                        UPDATE user_profiles 
                        SET preferred_platform = ?, preferred_style = ?, preferred_duration = ?, 
                            content_preferences = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE user_id = ?
                    """, (
                        profile.preferred_platform,
                        profile.preferred_style,
                        profile.preferred_duration,
                        json.dumps(profile.content_preferences) if profile.content_preferences else None,
                        profile.user_id
                    ))
            else:
                # 創建新記錄
                if use_postgresql:
                    cursor.execute("""
                        INSERT INTO user_profiles 
                        (user_id, preferred_platform, preferred_style, preferred_duration, content_preferences)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (
                        profile.user_id,
                        profile.preferred_platform,
                        profile.preferred_style,
                        profile.preferred_duration,
                        json.dumps(profile.content_preferences) if profile.content_preferences else None
                    ))
                else:
                    cursor.execute("""
                        INSERT INTO user_profiles 
                        (user_id, preferred_platform, preferred_style, preferred_duration, content_preferences)
                        VALUES (?, ?, ?, ?, ?)
                    """, (
                        profile.user_id,
                        profile.preferred_platform,
                        profile.preferred_style,
                        profile.preferred_duration,
                        json.dumps(profile.content_preferences) if profile.content_preferences else None
                    ))
            
            if not use_postgresql:
                conn.commit()
            conn.close()
            return {"message": "Profile saved successfully", "user_id": profile.user_id}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/generations")
    async def save_generation(generation: Generation, current_user_id: Optional[str] = Depends(get_current_user)):
        """保存生成內容並檢查去重"""
        if not current_user_id or current_user_id != generation.user_id:
            return JSONResponse({"error": "無權限儲存至此用戶"}, status_code=403)
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # 生成去重哈希
            dedup_hash = generate_dedup_hash(
                generation.content, 
                generation.platform, 
                generation.topic
            )
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            # 檢查是否已存在相同內容
            if use_postgresql:
                cursor.execute("SELECT id FROM generations WHERE dedup_hash = %s", (dedup_hash,))
            else:
                cursor.execute("SELECT id FROM generations WHERE dedup_hash = ?", (dedup_hash,))
            existing = cursor.fetchone()
            
            if existing:
                return {
                    "message": "Similar content already exists",
                    "generation_id": existing[0],
                    "dedup_hash": dedup_hash,
                    "is_duplicate": True
                }
            
            # 生成新的 ID
            generation_id = hashlib.md5(f"{generation.user_id}_{get_taiwan_time().isoformat()}".encode()).hexdigest()[:12]
            
            # 保存新生成內容
            if use_postgresql:
                cursor.execute("""
                    INSERT INTO generations (id, user_id, content, platform, topic, dedup_hash)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (
                    generation_id,
                    generation.user_id,
                    generation.content,
                    generation.platform,
                    generation.topic,
                    dedup_hash
                ))
            else:
                cursor.execute("""
                    INSERT INTO generations (id, user_id, content, platform, topic, dedup_hash)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    generation_id,
                    generation.user_id,
                    generation.content,
                    generation.platform,
                    generation.topic,
                    dedup_hash
                ))
            
            if not use_postgresql:
                conn.commit()
            conn.close()
            
            return {
                "message": "Generation saved successfully",
                "generation_id": generation_id,
                "dedup_hash": dedup_hash,
                "is_duplicate": False
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/generations/{user_id}")
    async def get_user_generations(user_id: str, limit: int = 10, current_user_id: Optional[str] = Depends(get_current_user)):
        """獲取用戶的生成歷史"""
        if not current_user_id or current_user_id != user_id:
            return JSONResponse({"error": "無權限訪問此用戶資料"}, status_code=403)
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            if use_postgresql:
                cursor.execute("""
                    SELECT id, content, platform, topic, created_at 
                    FROM generations 
                    WHERE user_id = %s 
                    ORDER BY created_at DESC 
                    LIMIT %s
                """, (user_id, limit))
            else:
                cursor.execute("""
                    SELECT id, content, platform, topic, created_at 
                    FROM generations 
                    WHERE user_id = ? 
                    ORDER BY created_at DESC 
                    LIMIT ?
                """, (user_id, limit))
            
            rows = cursor.fetchall()
            conn.close()
            
            generations = []
            for row in rows:
                generations.append({
                    "id": row[0],
                    "content": row[1],
                    "platform": row[2],
                    "topic": row[3],
                    "created_at": row[4]
                })
            
            return {"generations": generations, "count": len(generations)}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/conversation/summary")
    async def create_conversation_summary(user_id: str, messages: List[ChatMessage], current_user_id: Optional[str] = Depends(get_current_user)):
        """創建對話摘要"""
        if not current_user_id or current_user_id != user_id:
            return JSONResponse({"error": "無權限"}, status_code=403)
        try:
            if not os.getenv("GEMINI_API_KEY"):
                return {"error": "Gemini API not configured"}
            
            # 準備對話內容
            conversation_text = "\n".join([f"{msg.role}: {msg.content}" for msg in messages])
            
            # 使用 Gemini 生成摘要
            model = genai.GenerativeModel(model_name)
            prompt = f"""
            請為以下對話生成一個簡潔的摘要（不超過100字），重點關注：
            1. 用戶的主要需求和偏好
            2. 討論的平台和主題
            3. 重要的風格要求
            
            對話內容：
            {conversation_text}
            """
            
            response = model.generate_content(prompt)
            summary = response.text if response else "無法生成摘要"
            
            # 保存到數據庫
            conn = get_db_connection()
            cursor = conn.cursor()

            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE

            message_cnt = len(messages)

            if use_postgresql:
                # PostgreSQL upsert：以 (user_id, created_at, summary) 近似去重，避免重複
                cursor.execute("""
                    INSERT INTO conversation_summaries (user_id, summary, conversation_type, created_at, message_count, updated_at)
                    VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                """, (
                    user_id, summary, classify_conversation(user_message=messages[-1].content if messages else "", ai_response=summary), get_taiwan_time(), message_cnt
                ))
            else:
                cursor.execute("""
                    INSERT OR REPLACE INTO conversation_summaries 
                    (user_id, summary, message_count, updated_at)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                """, (user_id, summary, message_cnt))
            
            if not use_postgresql:
                conn.commit()
            conn.close()
            
            return {
                "message": "Conversation summary created",
                "summary": summary,
                "message_count": message_cnt
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/conversation/summary/{user_id}")
    async def get_conversation_summary(user_id: str, current_user_id: Optional[str] = Depends(get_current_user)):
        """獲取用戶的對話摘要"""
        if not current_user_id or current_user_id != user_id:
            return JSONResponse({"error": "無權限訪問此用戶資料"}, status_code=403)
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT summary, message_count, created_at, updated_at 
                FROM conversation_summaries 
                WHERE user_id = ?
            """, (user_id,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {
                    "user_id": user_id,
                    "summary": row[0],
                    "message_count": row[1],
                    "created_at": row[2],
                    "updated_at": row[3]
                }
            else:
                return {"message": "No conversation summary found", "user_id": user_id}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    # ============ 帳單資訊相關 API ============

    @app.get("/api/user/orders/{user_id}")
    async def get_user_orders(user_id: str, current_user_id: Optional[str] = Depends(get_current_user)):
        """獲取用戶的購買記錄"""
        if current_user_id != user_id:
            return JSONResponse({"error": "無權限訪問此用戶資料"}, status_code=403)
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            if use_postgresql:
                cursor.execute("""
                    SELECT id, order_id, plan_type, amount, currency, payment_method, 
                           payment_status, paid_at, expires_at, invoice_number, 
                           invoice_type, vat_number, name, email, phone, note, created_at
                    FROM orders 
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                """, (user_id,))
            else:
                cursor.execute("""
                    SELECT id, order_id, plan_type, amount, currency, payment_method, 
                           payment_status, paid_at, expires_at, invoice_number, 
                           invoice_type, vat_number, name, email, phone, note, created_at
                    FROM orders 
                    WHERE user_id = ?
                    ORDER BY created_at DESC
                """, (user_id,))
            
            rows = cursor.fetchall()
            conn.close()
            
            orders = []
            for row in rows:
                orders.append({
                    "id": row[0],
                    "order_id": row[1],
                    "plan_type": row[2],
                    "amount": row[3],
                    "currency": row[4],
                    "payment_method": row[5],
                    "payment_status": row[6],
                    "paid_at": str(row[7]) if row[7] else None,
                    "expires_at": str(row[8]) if row[8] else None,
                    "invoice_number": row[9],
                    "invoice_type": row[10],
                    "vat_number": row[11],
                    "name": row[12],
                    "email": row[13],
                    "phone": row[14],
                    "note": row[15],
                    "created_at": str(row[16]) if row[16] else None
                })
            
            return {"orders": orders}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @app.get("/api/user/orders")
    async def get_my_orders(current_user_id: Optional[str] = Depends(get_current_user)):
        """獲取當前用戶的訂單列表（簡化版，自動從 token 取得 user_id）"""
        if not current_user_id:
            return JSONResponse({"error": "請先登入"}, status_code=401)
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            # 先檢查表結構，如果欄位不存在則使用基本欄位
            try:
                if use_postgresql:
                    # 檢查是否有新欄位
                    cursor.execute("""
                        SELECT column_name 
                        FROM information_schema.columns 
                        WHERE table_name = 'orders' AND column_name IN ('vat_number', 'name', 'email', 'phone', 'note')
                    """)
                    existing_columns = [row[0] for row in cursor.fetchall()]
                    has_new_columns = all(col in existing_columns for col in ['vat_number', 'name', 'email', 'phone', 'note'])
                else:
                    # SQLite: 檢查表結構
                    cursor.execute("PRAGMA table_info(orders)")
                    columns_info = cursor.fetchall()
                    column_names = [col[1] for col in columns_info]
                    has_new_columns = all(col in column_names for col in ['vat_number', 'name', 'email', 'phone', 'note'])
            except Exception as e:
                logger.warning(f"檢查表結構失敗，使用基本欄位: {e}")
                has_new_columns = False
            
            # 根據表結構選擇查詢
            if has_new_columns:
                if use_postgresql:
                    cursor.execute("""
                        SELECT id, order_id, plan_type, amount, currency, payment_method, 
                               payment_status, paid_at, expires_at, invoice_number, 
                               invoice_type, vat_number, name, email, phone, note, created_at
                        FROM orders 
                        WHERE user_id = %s
                        ORDER BY created_at DESC
                    """, (current_user_id,))
                else:
                    cursor.execute("""
                        SELECT id, order_id, plan_type, amount, currency, payment_method, 
                               payment_status, paid_at, expires_at, invoice_number, 
                               invoice_type, vat_number, name, email, phone, note, created_at
                        FROM orders 
                        WHERE user_id = ?
                        ORDER BY created_at DESC
                    """, (current_user_id,))
            else:
                # 使用基本欄位（向後兼容）
                if use_postgresql:
                    cursor.execute("""
                        SELECT id, order_id, plan_type, amount, currency, payment_method, 
                               payment_status, paid_at, expires_at, invoice_number, 
                               invoice_type, created_at
                        FROM orders 
                        WHERE user_id = %s
                        ORDER BY created_at DESC
                    """, (current_user_id,))
                else:
                    cursor.execute("""
                        SELECT id, order_id, plan_type, amount, currency, payment_method, 
                               payment_status, paid_at, expires_at, invoice_number, 
                               invoice_type, created_at
                        FROM orders 
                        WHERE user_id = ?
                        ORDER BY created_at DESC
                    """, (current_user_id,))
            
            rows = cursor.fetchall()
            conn.close()
            
            orders = []
            for row in rows:
                if has_new_columns and len(row) >= 17:
                    # 有新欄位
                    orders.append({
                        "id": row[0],
                        "order_id": row[1],
                        "plan_type": row[2],
                        "amount": row[3],
                        "currency": row[4],
                        "payment_method": row[5],
                        "payment_status": row[6],
                        "paid_at": str(row[7]) if row[7] else None,
                        "expires_at": str(row[8]) if row[8] else None,
                        "invoice_number": row[9],
                        "invoice_type": row[10],
                        "vat_number": row[11],
                        "name": row[12],
                        "email": row[13],
                        "phone": row[14],
                        "note": row[15],
                        "created_at": str(row[16]) if row[16] else None
                    })
                else:
                    # 基本欄位（向後兼容）
                    orders.append({
                        "id": row[0],
                        "order_id": row[1],
                        "plan_type": row[2],
                        "amount": row[3],
                        "currency": row[4],
                        "payment_method": row[5],
                        "payment_status": row[6],
                        "paid_at": str(row[7]) if row[7] else None,
                        "expires_at": str(row[8]) if row[8] else None,
                        "invoice_number": row[9],
                        "invoice_type": row[10],
                        "vat_number": None,
                        "name": None,
                        "email": None,
                        "phone": None,
                        "note": None,
                        "created_at": str(row[11]) if len(row) > 11 and row[11] else None
                    })
            
            return {"orders": orders}
        except Exception as e:
            logger.error(f"獲取訂單列表失敗: {e}", exc_info=True)
            return JSONResponse({"error": "服務器錯誤，請稍後再試"}, status_code=500)

    @app.get("/api/user/subscription")
    async def get_subscription_status(current_user_id: Optional[str] = Depends(get_current_user)):
        """獲取當前用戶的訂閱狀態（簡化版，自動從 token 取得 user_id）"""
        if not current_user_id:
            return JSONResponse({"error": "請先登入"}, status_code=401)
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            # 查詢訂閱狀態
            if use_postgresql:
                cursor.execute(
                    "SELECT is_subscribed FROM user_auth WHERE user_id = %s",
                    (current_user_id,)
                )
            else:
                cursor.execute(
                    "SELECT is_subscribed FROM user_auth WHERE user_id = ?",
                    (current_user_id,)
                )
            
            user_row = cursor.fetchone()
            is_subscribed = user_row[0] if user_row and user_row[0] else False
            
            # 查詢授權資訊
            if use_postgresql:
                cursor.execute("""
                    SELECT tier, seats, source, start_at, expires_at, status
                    FROM licenses 
                    WHERE user_id = %s AND status = 'active'
                    ORDER BY created_at DESC
                    LIMIT 1
                """, (current_user_id,))
            else:
                cursor.execute("""
                    SELECT tier, seats, source, start_at, expires_at, status
                    FROM licenses 
                    WHERE user_id = ? AND status = 'active'
                    ORDER BY created_at DESC
                    LIMIT 1
                """, (current_user_id,))
            
            license_row = cursor.fetchone()
            conn.close()
            
            result = {
                "user_id": current_user_id,
                "is_subscribed": bool(is_subscribed),
                "tier": None,
                "expires_at": None,
                "status": "inactive"
            }
            
            if license_row:
                result.update({
                    "tier": license_row[0],
                    "seats": license_row[1],
                    "source": license_row[2],
                    "start_at": str(license_row[3]) if license_row[3] else None,
                    "expires_at": str(license_row[4]) if license_row[4] else None,
                    "status": license_row[5] or "active"
                })
            
            return result
        except Exception as e:
            logger.error(f"獲取訂閱狀態失敗: {e}", exc_info=True)
            return JSONResponse({"error": "服務器錯誤，請稍後再試"}, status_code=500)

    @app.get("/api/user/license/{user_id}")
    async def get_user_license(user_id: str, current_user_id: Optional[str] = Depends(get_current_user)):
        """獲取用戶的授權資訊"""
        if current_user_id != user_id:
            return JSONResponse({"error": "無權限訪問此用戶資料"}, status_code=403)
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            if use_postgresql:
                cursor.execute("""
                    SELECT tier, seats, source, start_at, expires_at, status
                    FROM licenses 
                    WHERE user_id = %s AND status = 'active'
                    ORDER BY created_at DESC
                    LIMIT 1
                """, (user_id,))
            else:
                cursor.execute("""
                    SELECT tier, seats, source, start_at, expires_at, status
                    FROM licenses 
                    WHERE user_id = ? AND status = 'active'
                    ORDER BY created_at DESC
                    LIMIT 1
                """, (user_id,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {
                    "user_id": user_id,
                    "tier": row[0],
                    "seats": row[1],
                    "source": row[2],
                    "start_at": str(row[3]),
                    "expires_at": str(row[4]),
                    "status": row[5]
                }
            else:
                return {"user_id": user_id, "tier": "none", "expires_at": None}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @app.post("/api/admin/auth/login")
    @rate_limit("5/minute")
    async def admin_login(request: Request):
        """管理員帳號密碼登入"""
        try:
            body = await request.json()
            email = body.get("email", "").strip().lower()
            password = body.get("password", "").strip()
            
            if not email or not password:
                return JSONResponse({"error": "請輸入帳號和密碼"}, status_code=400)
            
            conn = get_db_connection()
            cursor = conn.cursor()
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            # 檢查管理員帳號
            if use_postgresql:
                cursor.execute("""
                    SELECT id, email, password_hash, name, is_active 
                    FROM admin_accounts 
                    WHERE email = %s
                """, (email,))
            else:
                cursor.execute("""
                    SELECT id, email, password_hash, name, is_active 
                    FROM admin_accounts 
                    WHERE email = ?
                """, (email,))
            
            admin_account = cursor.fetchone()
            conn.close()
            
            if not admin_account:
                return JSONResponse({"error": "帳號或密碼錯誤"}, status_code=401)
            
            account_id, account_email, password_hash, account_name, is_active = admin_account
            
            if not is_active:
                return JSONResponse({"error": "帳號已停用"}, status_code=403)
            
            # 驗證密碼（使用 SHA256）
            input_password_hash = hashlib.sha256(password.encode()).hexdigest()
            if input_password_hash != password_hash:
                return JSONResponse({"error": "帳號或密碼錯誤"}, status_code=401)
            
            # 生成 user_id（與 OAuth 登入一致）
            user_id = generate_user_id(email)
            
            # 確保用戶資料存在於 user_auth 表中
            conn = get_db_connection()
            cursor = conn.cursor()
            
            if use_postgresql:
                cursor.execute("""
                    INSERT INTO user_auth (user_id, email, name, updated_at)
                    VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
                    ON CONFLICT (user_id) 
                    DO UPDATE SET 
                        email = EXCLUDED.email,
                        name = EXCLUDED.name,
                        updated_at = CURRENT_TIMESTAMP
                """, (user_id, account_email, account_name or "管理員"))
            else:
                cursor.execute("""
                    INSERT OR REPLACE INTO user_auth (user_id, email, name, updated_at)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                """, (user_id, account_email, account_name or "管理員"))
            
            conn.commit()
            conn.close()
            
            # 生成 access token
            access_token = generate_access_token(user_id)
            
            return {
                "access_token": access_token,
                "token_type": "bearer",
                "user_id": user_id,
                "email": account_email,
                "name": account_name or "管理員",
                "expires_in": 86400  # 24小時
            }
        except Exception as e:
            print(f"管理員登入錯誤: {e}")
            return JSONResponse({"error": str(e)}, status_code=500)

    @app.get("/api/admin/orders")
    async def get_all_orders(admin_user: str = Depends(get_admin_user)):
        """獲取所有訂單記錄（管理員用）"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            if use_postgresql:
                cursor.execute("""
                    SELECT o.id, o.user_id, o.order_id, o.plan_type, o.amount, 
                           o.currency, o.payment_method, o.payment_status, 
                           o.paid_at, o.expires_at, o.invoice_number, o.created_at,
                           ua.name, ua.email
                    FROM orders o
                    LEFT JOIN user_auth ua ON o.user_id = ua.user_id
                    ORDER BY o.created_at DESC
                    LIMIT 100
                """)
            else:
                cursor.execute("""
                    SELECT o.id, o.user_id, o.order_id, o.plan_type, o.amount, 
                           o.currency, o.payment_method, o.payment_status, 
                           o.paid_at, o.expires_at, o.invoice_number, o.created_at,
                           ua.name, ua.email
                    FROM orders o
                    LEFT JOIN user_auth ua ON o.user_id = ua.user_id
                    ORDER BY o.created_at DESC
                    LIMIT 100
                """)
            
            orders = []
            for row in cursor.fetchall():
                orders.append({
                    "id": row[0],
                    "user_id": row[1],
                    "order_id": row[2],
                    "plan_type": row[3],
                    "amount": row[4],
                    "currency": row[5],
                    "payment_method": row[6],
                    "payment_status": row[7],
                    "paid_at": str(row[8]) if row[8] else None,
                    "expires_at": str(row[9]) if row[9] else None,
                    "invoice_number": row[10],
                    "invoice_type": row[11],
                    "vat_number": row[12],
                    "name": row[13],  # 訂單填寫的姓名
                    "email": row[14],  # 訂單填寫的 Email
                    "phone": row[15],  # 訂單填寫的手機
                    "note": row[16],  # 備註
                    "created_at": str(row[17]) if row[17] else None,
                    "user_name": row[18] or "未知用戶",  # 用戶帳號的姓名
                    "user_email": row[19] or ""  # 用戶帳號的 Email
                })
            
            conn.close()
            return {"orders": orders}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    # ===== BYOK (Bring Your Own Key) API 端點 =====
    
    @app.post("/api/user/llm-keys")
    @rate_limit("5/minute")
    async def save_llm_key(request: Request, current_user_id: Optional[str] = Depends(get_current_user)):
        """保存用戶的 LLM API Key（Rate Limit: 5/分鐘）"""
        if not current_user_id:
            return JSONResponse({"error": "請先登入"}, status_code=401)
        
        if not CRYPTOGRAPHY_AVAILABLE:
            return JSONResponse({"error": "BYOK 功能不可用，請安裝 cryptography"}, status_code=500)
        
        try:
            body = await request.json()
            user_id = body.get("user_id")
            provider = body.get("provider", "gemini")  # 'gemini' or 'openai'
            api_key = body.get("api_key")
            
            if not user_id:
                return JSONResponse({"error": "缺少 user_id"}, status_code=400)
            
            if user_id != current_user_id:
                return JSONResponse({"error": "無權限訪問其他用戶的資料"}, status_code=403)
            
            if not api_key:
                return JSONResponse({"error": "缺少 api_key"}, status_code=400)
            
            if provider not in ["gemini", "openai"]:
                return JSONResponse({"error": "不支援的 provider，只支援 'gemini' 或 'openai'"}, status_code=400)
            
            # 驗證用戶 ID 格式
            if not validate_user_id(user_id):
                return JSONResponse({"error": "用戶 ID 格式無效"}, status_code=400)
            
            # 驗證 API Key 格式
            if not validate_api_key(api_key, provider):
                return JSONResponse({"error": "API Key 格式無效"}, status_code=400)
            
            # 加密 API Key
            encrypted_key = encrypt_api_key(api_key)
            
            # 提取最後4位（用於顯示）
            last4 = api_key[-4:] if len(api_key) >= 4 else "****"
            
            # 保存到資料庫（使用 INSERT OR REPLACE / ON CONFLICT）
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            if use_postgresql:
                cursor.execute("""
                    INSERT INTO user_llm_keys (user_id, provider, encrypted_key, last4, updated_at)
                    VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
                    ON CONFLICT (user_id, provider) 
                    DO UPDATE SET encrypted_key = EXCLUDED.encrypted_key, 
                                  last4 = EXCLUDED.last4, 
                                  updated_at = CURRENT_TIMESTAMP
                """, (user_id, provider, encrypted_key, last4))
            else:
                cursor.execute("""
                    INSERT OR REPLACE INTO user_llm_keys 
                    (user_id, provider, encrypted_key, last4, updated_at)
                    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, (user_id, provider, encrypted_key, last4))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return {"message": "API Key 已安全保存", "provider": provider, "last4": last4}
        
        except ValueError as e:
            # 用戶輸入錯誤，返回友好提示
            logger.warning(f"保存 LLM Key 輸入錯誤: {e}, user_id: {current_user_id}")
            return JSONResponse({"error": "輸入格式錯誤，請檢查後重試"}, status_code=400)
        except Exception as e:
            # 記錄詳細錯誤到日誌（不返回給用戶）
            logger.error(f"保存 LLM Key 失敗: {e}", exc_info=True)
            # 返回通用錯誤信息
            return JSONResponse({"error": "服務器錯誤，請稍後再試"}, status_code=500)
    
    @app.get("/api/user/llm-keys/{user_id}")
    async def get_llm_keys(user_id: str, current_user_id: Optional[str] = Depends(get_current_user)):
        """獲取用戶已保存的 LLM Keys（只返回 last4，不返回完整金鑰）"""
        if not current_user_id:
            return JSONResponse({"error": "請先登入"}, status_code=401)
        
        if user_id != current_user_id:
            return JSONResponse({"error": "無權限訪問其他用戶的資料"}, status_code=403)
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            if use_postgresql:
                cursor.execute(
                    "SELECT provider, last4, created_at, updated_at FROM user_llm_keys WHERE user_id = %s",
                    (user_id,)
                )
            else:
                cursor.execute(
                    "SELECT provider, last4, created_at, updated_at FROM user_llm_keys WHERE user_id = ?",
                    (user_id,)
                )
            
            keys = []
            for row in cursor.fetchall():
                keys.append({
                    "provider": row[0],
                    "last4": row[1],
                    "created_at": row[2].isoformat() if row[2] else None,
                    "updated_at": row[3].isoformat() if row[3] else None
                })
            
            cursor.close()
            conn.close()
            
            return {"keys": keys}
        
        except Exception as e:
            logger.error(f"獲取 LLM Keys 失敗: {e}", exc_info=True)
            return JSONResponse({"error": "服務器錯誤，請稍後再試"}, status_code=500)
    
    @app.post("/api/user/llm-keys/test")
    @rate_limit("3/minute")
    async def test_llm_key(request: Request, current_user_id: Optional[str] = Depends(get_current_user)):
        """測試 API Key 是否有效（不保存）（Rate Limit: 3/分鐘）"""
        if not current_user_id:
            return JSONResponse({"error": "請先登入"}, status_code=401)
        
        try:
            body = await request.json()
            provider = body.get("provider", "gemini")
            api_key = body.get("api_key")
            
            if not api_key:
                return JSONResponse({"error": "缺少 api_key"}, status_code=400)
            
            if provider == "gemini":
                # 測試 Gemini API Key
                try:
                    import google.generativeai as genai
                    genai.configure(api_key=api_key)
                    model = genai.GenerativeModel("gemini-2.0-flash-exp")
                    response = model.generate_content("test", request_options={"timeout": 5})
                    return {"valid": True, "message": "Gemini API Key 有效"}
                except Exception as e:
                    return {"valid": False, "error": f"Gemini API Key 無效: {str(e)}"}
            
            elif provider == "openai":
                # 測試 OpenAI API Key
                try:
                    import openai
                    client = openai.OpenAI(api_key=api_key)
                    response = client.models.list()
                    return {"valid": True, "message": "OpenAI API Key 有效"}
                except Exception as e:
                    return {"valid": False, "error": f"OpenAI API Key 無效: {str(e)}"}
            
            else:
                return JSONResponse({"error": "不支援的 provider"}, status_code=400)
        
        except Exception as e:
            logger.error(f"測試 LLM Key 失敗: {e}", exc_info=True)
            return JSONResponse({"error": "服務器錯誤，請稍後再試"}, status_code=500)
    
    @app.delete("/api/user/llm-keys/{user_id}")
    async def delete_llm_key(user_id: str, request: Request, current_user_id: Optional[str] = Depends(get_current_user)):
        """刪除用戶的 LLM API Key"""
        if not current_user_id:
            return JSONResponse({"error": "請先登入"}, status_code=401)
        
        if user_id != current_user_id:
            return JSONResponse({"error": "無權限訪問其他用戶的資料"}, status_code=403)
        
        try:
            body = await request.json()
            provider = body.get("provider", "gemini")
            
            conn = get_db_connection()
            cursor = conn.cursor()
            
            database_url = os.getenv("DATABASE_URL")
            use_postgresql = database_url and "postgresql://" in database_url and PSYCOPG2_AVAILABLE
            
            if use_postgresql:
                cursor.execute(
                    "DELETE FROM user_llm_keys WHERE user_id = %s AND provider = %s",
                    (user_id, provider)
                )
            else:
                cursor.execute(
                    "DELETE FROM user_llm_keys WHERE user_id = ? AND provider = ?",
                    (user_id, provider)
                )
            
            deleted_count = cursor.rowcount
            conn.commit()
            cursor.close()
            conn.close()
            
            if deleted_count > 0:
                return {"message": "API Key 已刪除", "provider": provider}
            else:
                return JSONResponse({"error": "找不到指定的 API Key"}, status_code=404)
        
        except Exception as e:
            logger.error(f"刪除 LLM Key 失敗: {e}", exc_info=True)
            return JSONResponse({"error": "服務器錯誤，請稍後再試"}, status_code=500)

    return app

app = create_app()

# 注意：在 Zeabur 部署時，使用 Dockerfile 中的 uvicorn 命令啟動
# 這個區塊主要用於本地開發
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    print(f"INFO: Starting Uvicorn locally on host=0.0.0.0, port={port}")
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=port,
        log_level="info",
        access_log=True,
        workers=1
    )


