# -*- coding: utf-8 -*-
"""
RAG (檢索增強生成) 模組
使用向量檢索來增強 LLM 的生成能力
"""
import os
import json
import sqlite3
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
import numpy as np
from collections import defaultdict

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    print("WARNING: google.generativeai not available, RAG embedding will be disabled")

class SimpleVectorStore:
    """簡單的本地向量儲存（使用 SQLite）"""
    
    def __init__(self, db_path: str = "data/rag_vectors.db"):
        self.db_path = db_path
        self._ensure_db()
    
    def _ensure_db(self):
        """確保資料庫和表存在"""
        os.makedirs(os.path.dirname(self.db_path) if os.path.dirname(self.db_path) else ".", exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 向量表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vectors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content_id TEXT NOT NULL,
                content_type TEXT NOT NULL,
                user_id TEXT,
                content_text TEXT NOT NULL,
                embedding TEXT NOT NULL,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(content_id, content_type, user_id)
            )
        """)
        
        # 索引
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_content_type_user 
            ON vectors(content_type, user_id)
        """)
        
        conn.commit()
        conn.close()
    
    def add_vector(self, content_id: str, content_type: str, content_text: str, 
                   embedding: List[float], user_id: Optional[str] = None, 
                   metadata: Optional[Dict] = None):
        """添加向量"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        embedding_json = json.dumps(embedding)
        metadata_json = json.dumps(metadata) if metadata else None
        
        cursor.execute("""
            INSERT OR REPLACE INTO vectors 
            (content_id, content_type, user_id, content_text, embedding, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (content_id, content_type, user_id, content_text, embedding_json, metadata_json))
        
        conn.commit()
        conn.close()
    
    def search_similar(self, query_embedding: List[float], content_type: Optional[str] = None,
                      user_id: Optional[str] = None, limit: int = 5, 
                      min_similarity: float = 0.5) -> List[Dict[str, Any]]:
        """搜尋相似向量"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 構建查詢
        query = "SELECT content_id, content_type, user_id, content_text, embedding, metadata FROM vectors WHERE 1=1"
        params = []
        
        if content_type:
            query += " AND content_type = ?"
            params.append(content_type)
        
        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        # 計算相似度
        results = []
        query_vec = np.array(query_embedding)
        
        for row in rows:
            content_id, ct, uid, content_text, embedding_json, metadata_json = row
            embedding = json.loads(embedding_json)
            vec = np.array(embedding)
            
            # 計算餘弦相似度
            similarity = np.dot(query_vec, vec) / (np.linalg.norm(query_vec) * np.linalg.norm(vec))
            
            if similarity >= min_similarity:
                metadata = json.loads(metadata_json) if metadata_json else {}
                results.append({
                    'content_id': content_id,
                    'content_type': ct,
                    'user_id': uid,
                    'content_text': content_text,
                    'similarity': float(similarity),
                    'metadata': metadata
                })
        
        # 按相似度排序
        results.sort(key=lambda x: x['similarity'], reverse=True)
        return results[:limit]
    
    def delete_by_content_id(self, content_id: str, content_type: str, user_id: Optional[str] = None):
        """刪除向量"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if user_id:
            cursor.execute("DELETE FROM vectors WHERE content_id = ? AND content_type = ? AND user_id = ?",
                         (content_id, content_type, user_id))
        else:
            cursor.execute("DELETE FROM vectors WHERE content_id = ? AND content_type = ?",
                         (content_id, content_type))
        
        conn.commit()
        conn.close()


class RAGSystem:
    """RAG 系統主類"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self.vector_store = SimpleVectorStore()
        
        if GEMINI_AVAILABLE and self.api_key:
            genai.configure(api_key=self.api_key)
            # Gemini 使用 genai.embed_content，不需要 GenerativeModel
            self.embedding_model = None
        else:
            self.embedding_model = None
    
    def get_embedding(self, text: str) -> Optional[List[float]]:
        """獲取文本的向量嵌入"""
        if not self.api_key or not text or not GEMINI_AVAILABLE:
            return None
        
        try:
            # 使用 Gemini Embedding API
            # Gemini 使用 genai.embed_content 方法
            result = genai.embed_content(
                model='models/text-embedding-004',
                content=text,
                task_type='retrieval_document'
            )
            
            # 處理返回結果
            if result:
                # 檢查不同的返回格式
                if isinstance(result, dict) and 'embedding' in result:
                    return result['embedding']
                elif isinstance(result, list) and len(result) > 0:
                    # 如果返回列表，取第一個元素
                    if isinstance(result[0], list):
                        return result[0]
                    elif isinstance(result[0], dict) and 'embedding' in result[0]:
                        return result[0]['embedding']
                    else:
                        return result[0] if isinstance(result[0], (list, tuple)) else None
                elif hasattr(result, 'embedding'):
                    return result.embedding
        except AttributeError:
            # 如果 genai.embed_content 不存在，嘗試使用其他方法
            try:
                # 備用方案：使用 GenerativeModel（如果支援）
                if self.embedding_model:
                    result = self.embedding_model.embed_content(text)
                    if result and 'embedding' in result:
                        return result['embedding']
            except:
                pass
        except Exception as e:
            print(f"ERROR: 獲取 embedding 失敗: {e}")
            # 如果 Gemini embedding 不可用，返回 None（RAG 功能將被禁用）
            return None
        
        return None
    
    def index_script(self, script_id: str, script_data: Dict[str, Any], user_id: Optional[str] = None):
        """索引腳本"""
        # 檢查是否啟用自動索引
        auto_index = os.getenv("RAG_AUTO_INDEX", "true").lower() == "true"
        if not auto_index:
            return
        
        if not script_data:
            return
        
        # 提取文本內容
        content_parts = []
        if script_data.get('title'):
            content_parts.append(f"標題：{script_data['title']}")
        if script_data.get('content'):
            content_parts.append(script_data['content'])
        if script_data.get('script_data'):
            script_info = script_data['script_data']
            if isinstance(script_info, dict):
                if script_info.get('hook'):
                    content_parts.append(f"Hook: {script_info['hook']}")
                if script_info.get('value'):
                    content_parts.append(f"Value: {script_info['value']}")
                if script_info.get('cta'):
                    content_parts.append(f"CTA: {script_info['cta']}")
        
        content_text = "\n".join(content_parts)
        if not content_text.strip():
            return
        
        # 獲取 embedding
        embedding = self.get_embedding(content_text)
        if not embedding:
            return
        
        # 儲存向量
        metadata = {
            'platform': script_data.get('platform'),
            'topic': script_data.get('topic'),
            'profile': script_data.get('profile'),
            'created_at': script_data.get('created_at')
        }
        
        self.vector_store.add_vector(
            content_id=script_id,
            content_type='script',
            content_text=content_text,
            embedding=embedding,
            user_id=user_id,
            metadata=metadata
        )
    
    def index_ip_planning(self, result_id: str, result_data: Dict[str, Any], user_id: Optional[str] = None):
        """索引 IP 規劃結果"""
        # 檢查是否啟用自動索引
        auto_index = os.getenv("RAG_AUTO_INDEX", "true").lower() == "true"
        if not auto_index:
            return
        
        if not result_data:
            return
        
        content_text = result_data.get('content', '')
        if not content_text.strip():
            return
        
        # 獲取 embedding
        embedding = self.get_embedding(content_text)
        if not embedding:
            return
        
        # 儲存向量
        metadata = {
            'result_type': result_data.get('result_type'),
            'title': result_data.get('title'),
            'created_at': result_data.get('created_at')
        }
        
        self.vector_store.add_vector(
            content_id=result_id,
            content_type='ip_planning',
            content_text=content_text,
            embedding=embedding,
            user_id=user_id,
            metadata=metadata
        )
    
    def search_relevant_content(self, query: str, user_id: Optional[str] = None,
                               content_types: Optional[List[str]] = None,
                               limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """搜尋相關內容"""
        if not query or not query.strip():
            return []
        
        # 從環境變數讀取配置（支援成本優化）
        search_limit = limit or int(os.getenv("RAG_SEARCH_LIMIT", "3"))
        min_similarity = float(os.getenv("RAG_MIN_SIMILARITY", "0.3"))
        
        # 獲取查詢的 embedding
        query_embedding = self.get_embedding(query)
        if not query_embedding:
            return []
        
        # 搜尋所有類型的內容
        all_results = []
        types_to_search = content_types or ['script', 'ip_planning']
        
        for content_type in types_to_search:
            results = self.vector_store.search_similar(
                query_embedding=query_embedding,
                content_type=content_type,
                user_id=user_id,
                limit=search_limit,
                min_similarity=min_similarity
            )
            all_results.extend(results)
        
        # 按相似度排序並返回前 N 個
        all_results.sort(key=lambda x: x['similarity'], reverse=True)
        return all_results[:search_limit]
    
    def format_retrieved_content(self, results: List[Dict[str, Any]]) -> str:
        """格式化檢索結果為 prompt 格式"""
        if not results:
            return ""
        
        formatted_parts = []
        formatted_parts.append("📚 相關歷史內容參考：")
        
        for i, result in enumerate(results, 1):
            content_type = result['content_type']
            content_text = result['content_text']
            similarity = result['similarity']
            metadata = result.get('metadata', {})
            
            if content_type == 'script':
                type_name = "腳本"
                title = metadata.get('title', '無標題')
                formatted_parts.append(f"\n{i}. 【{type_name}】{title} (相似度: {similarity:.2f})")
                formatted_parts.append(f"   {content_text[:300]}...")  # 限制長度
            elif content_type == 'ip_planning':
                type_name = "IP規劃"
                result_type = metadata.get('result_type', '')
                type_map = {'profile': '帳號定位', 'plan': '選題方向', 'scripts': '一週腳本'}
                type_name_full = type_map.get(result_type, type_name)
                formatted_parts.append(f"\n{i}. 【{type_name_full}】 (相似度: {similarity:.2f})")
                formatted_parts.append(f"   {content_text[:300]}...")  # 限制長度
        
        return "\n".join(formatted_parts)


# 全局 RAG 實例（使用系統 key）
_system_rag_instance: Optional[RAGSystem] = None

# 用戶專屬 RAG 實例緩存（key: user_id, value: RAGSystem）
_user_rag_instances: Dict[str, RAGSystem] = {}

def get_rag_instance(user_id: Optional[str] = None, user_api_key: Optional[str] = None) -> Optional[RAGSystem]:
    """
    獲取 RAG 實例
    
    Args:
        user_id: 用戶 ID（如果提供，會優先使用用戶的 key）
        user_api_key: 用戶的 API Key（如果提供，會使用此 key）
    
    Returns:
        RAGSystem 實例或 None
    """
    global _system_rag_instance, _user_rag_instances
    
    # 檢查是否啟用 RAG
    enable_rag = os.getenv("ENABLE_RAG", "true").lower() == "true"
    if not enable_rag:
        return None
    
    # 優先使用用戶的 key（BYOK）
    if user_id and user_api_key:
        # 檢查緩存
        if user_id in _user_rag_instances:
            return _user_rag_instances[user_id]
        
        # 創建用戶專屬的 RAG 實例
        try:
            user_rag = RAGSystem(api_key=user_api_key)
            _user_rag_instances[user_id] = user_rag
            return user_rag
        except Exception as e:
            print(f"WARNING: 無法為用戶 {user_id} 創建 RAG 實例: {e}")
            # 如果用戶 key 失敗，回退到系統 key
            pass
    
    # 使用系統 key（全局實例）
    if _system_rag_instance is None:
        api_key = os.getenv("GEMINI_API_KEY")
        if api_key:
            _system_rag_instance = RAGSystem(api_key=api_key)
            print("INFO: RAG 系統已啟用（使用系統 key）")
        else:
            print("WARNING: GEMINI_API_KEY not found, RAG will be disabled")
            return None
    
    return _system_rag_instance

