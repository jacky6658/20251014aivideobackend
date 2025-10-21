# -*- coding: utf-8 -*-
"""
短期記憶（STM）模組
管理對話上下文、摘要壓縮、TTL 過期
"""
import json
import time
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

class ShortTermMemory:
    """
    短期記憶管理器
    - 維持最近 10-30 輪對話
    - 自動壓縮超過 token 限制的對話
    - 48 小時 TTL 自動過期
    """
    
    def __init__(self, max_turns: int = 20, max_tokens: int = 2000, ttl_hours: int = 48):
        """
        初始化 STM
        
        Args:
            max_turns: 最多保留的對話輪次
            max_tokens: token 上限（超過則壓縮）
            ttl_hours: 記憶存活時間（小時）
        """
        self.max_turns = max_turns
        self.max_tokens = max_tokens
        self.ttl_hours = ttl_hours
        # 使用記憶體儲存（簡化版，生產環境可用 Redis）
        self.memory_store: Dict[str, Dict[str, Any]] = {}
    
    def get_session_id(self, user_id: str) -> str:
        """生成 session ID"""
        return f"stm:{user_id}"
    
    def load_memory(self, user_id: str) -> Dict[str, Any]:
        """
        載入短期記憶
        
        Returns:
            {
                "recent_turns": [...],  # 最近對話
                "last_summary": "...",  # 舊對話摘要
                "state": {},            # 臨時狀態
                "updated_at": timestamp
            }
        """
        session_id = self.get_session_id(user_id)
        memory = self.memory_store.get(session_id, {
            "recent_turns": [],
            "last_summary": "",
            "state": {},
            "updated_at": time.time()
        })
        
        # 檢查 TTL
        if time.time() - memory.get("updated_at", 0) > self.ttl_hours * 3600:
            # 過期，重置記憶
            return {
                "recent_turns": [],
                "last_summary": "",
                "state": {},
                "updated_at": time.time()
            }
        
        return memory
    
    def save_memory(self, user_id: str, memory: Dict[str, Any]) -> None:
        """儲存短期記憶"""
        session_id = self.get_session_id(user_id)
        memory["updated_at"] = time.time()
        self.memory_store[session_id] = memory
    
    def add_turn(self, user_id: str, user_message: str, ai_response: str, metadata: Optional[Dict] = None) -> None:
        """
        新增一輪對話
        
        Args:
            user_id: 用戶 ID
            user_message: 用戶訊息
            ai_response: AI 回覆
            metadata: 額外資訊（平台、主題等）
        """
        memory = self.load_memory(user_id)
        
        # 新增對話
        turn = {
            "user": user_message,
            "assistant": ai_response,
            "timestamp": datetime.now().isoformat(),
            "metadata": metadata or {}
        }
        memory["recent_turns"].append(turn)
        
        # 檢查是否超過限制
        if len(memory["recent_turns"]) > self.max_turns:
            # 壓縮最舊的對話
            memory = self._compress_memory(memory)
        
        self.save_memory(user_id, memory)
    
    def _compress_memory(self, memory: Dict[str, Any]) -> Dict[str, Any]:
        """
        壓縮記憶：將最舊的對話摘要化
        """
        if len(memory["recent_turns"]) <= self.max_turns:
            return memory
        
        # 取出最舊的 5 輪對話
        old_turns = memory["recent_turns"][:5]
        memory["recent_turns"] = memory["recent_turns"][5:]
        
        # 生成摘要
        summary_parts = []
        for turn in old_turns:
            user_msg = turn["user"][:50]
            ai_msg = turn["assistant"][:100]
            summary_parts.append(f"用戶：{user_msg}... | AI：{ai_msg}...")
        
        new_summary = "\n".join(summary_parts)
        
        # 合併到現有摘要
        if memory["last_summary"]:
            memory["last_summary"] += f"\n[更早的對話]\n{new_summary}"
        else:
            memory["last_summary"] = new_summary
        
        return memory
    
    def get_context_for_prompt(self, user_id: str) -> str:
        """
        為 prompt 生成上下文字串
        
        Returns:
            格式化的對話歷史
        """
        memory = self.load_memory(user_id)
        
        context_parts = []
        
        # 1. 舊對話摘要
        if memory["last_summary"]:
            context_parts.append(f"[對話摘要]\n{memory['last_summary']}\n")
        
        # 2. 最近對話
        if memory["recent_turns"]:
            context_parts.append("[最近對話]")
            for i, turn in enumerate(memory["recent_turns"][-10:], 1):  # 最多顯示 10 輪
                user_msg = turn["user"]
                ai_msg = turn["assistant"]
                context_parts.append(f"{i}. 用戶：{user_msg}")
                context_parts.append(f"   AI：{ai_msg[:200]}...")
        
        return "\n".join(context_parts) if context_parts else ""
    
    def get_recent_turns_for_history(self, user_id: str, limit: int = 5) -> List[Dict[str, str]]:
        """
        獲取最近對話，用於 Gemini API 的 history 參數
        
        Returns:
            [{"role": "user", "parts": "..."}, {"role": "model", "parts": "..."}]
        """
        memory = self.load_memory(user_id)
        
        history = []
        for turn in memory["recent_turns"][-limit:]:
            history.append({"role": "user", "parts": [turn["user"]]})
            history.append({"role": "model", "parts": [turn["assistant"]]})
        
        return history
    
    def clear_memory(self, user_id: str) -> None:
        """清除用戶的短期記憶"""
        session_id = self.get_session_id(user_id)
        if session_id in self.memory_store:
            del self.memory_store[session_id]
    
    def update_state(self, user_id: str, key: str, value: Any) -> None:
        """更新臨時狀態變數"""
        memory = self.load_memory(user_id)
        memory["state"][key] = value
        self.save_memory(user_id, memory)
    
    def get_state(self, user_id: str, key: str, default: Any = None) -> Any:
        """獲取臨時狀態變數"""
        memory = self.load_memory(user_id)
        return memory["state"].get(key, default)


# 全局 STM 實例
stm = ShortTermMemory(max_turns=20, max_tokens=2000, ttl_hours=48)

