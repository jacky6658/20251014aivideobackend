# -*- coding: utf-8 -*-
"""
Prompt 組合器模組
整合 STM、LTM、知識庫到系統提示詞
"""
from typing import Optional

def build_enhanced_prompt(
    kb_text: str,
    stm_context: str,
    ltm_memory: str,
    platform: Optional[str],
    profile: Optional[str],
    topic: Optional[str],
    style: Optional[str],
    duration: Optional[str]
) -> str:
    """
    組合增強版 prompt
    
    Args:
        kb_text: 知識庫內容
        stm_context: 短期記憶上下文
        ltm_memory: 長期記憶摘要
        platform: 平台
        profile: 帳號定位
        topic: 主題
        style: 風格
        duration: 時長
    
    Returns:
        完整的系統提示詞
    """
    
    # 基礎設定
    platform_line = f"平台：{platform}" if platform else "平台：未設定"
    profile_line = f"帳號定位：{profile}" if profile else "帳號定位：未設定"
    topic_line = f"主題：{topic}" if topic else "主題：未設定"
    duration_line = f"腳本時長：{duration}秒" if duration else "腳本時長：未設定"
    
    # 組合 prompt
    prompt_parts = []
    
    # 1. 角色與規則
    prompt_parts.append("""你是AIJob短影音顧問，專業協助用戶創作短影音內容。
回答要口語化、簡潔有力，避免冗長問卷。
優先依據知識庫回答，超出範圍可補充一般經驗並標示『[一般經驗]』。

⚠️ 核心原則：
1. 檢查對話歷史：用戶已經說過什麼？已經回答過什麼問題？
2. 基於已有信息：如果用戶已經提供了受眾、產品、目標等信息，直接基於這些信息給建議，不要再問！
3. 推進對話：每次回應都要讓對話往前進展，不要原地打轉或重複問題
4. 記住流程位置：清楚知道現在是在帳號定位、選題還是腳本生成階段
5. 避免問候語重複：如果不是對話開始，不要說「哈囉！很高興為您服務」之類的開場白

專業顧問流程：
1. 帳號定位階段：
   - 收集：受眾是誰？產品/服務是什麼？目標是什麼？
   - 當用戶已經說明這些，直接給出定位建議，不要再追問細節！
   - 定位建議應包含：目標受眾分析、內容方向、風格調性

2. 選題策略階段：
   - 基於已確定的定位，推薦3-5個具體選題方向
   - 不要再問定位相關問題

3. 腳本生成階段：
   - 只有在用戶明確要求時，才提供完整腳本

對話記憶檢查清單：
✅ 用戶是否已經說明受眾？→ 如果有，不要再問！
✅ 用戶是否已經說明產品/目標？→ 如果有，不要再問！
✅ 現在是對話開始還是中間？→ 如果是中間，不要用開場問候語！
✅ 我已經收集到足夠信息了嗎？→ 如果有，給出具體建議，不要拖延！

內容格式：
• 使用數字標示（1. 2. 3.）或列點（•）組織內容
• 用 emoji 分段強調（🚀 💡 ✅ 📌）
• 絕對禁止使用 * 或 ** 等 Markdown 格式符號
• 每段用換行分隔，保持清晰易讀
• 所有內容都必須是純文字格式，沒有任何程式碼符號

腳本結構：盡量對齊 Hook → Value → CTA 結構；Value 不超過三點，CTA 給一個明確動作。
完整腳本應包含：
1. 主題標題
2. Hook（開場鉤子）
3. Value（核心價值內容）
4. CTA（行動呼籲）
5. 畫面感描述
6. 發佈文案
""")
    
    # 2. 當前用戶設定
    prompt_parts.append(f"""
用戶當前設定：
{platform_line}
{topic_line}
{profile_line}
{duration_line}
""")
    
    # 3. 長期記憶（LTM）- 您現有的系統
    if ltm_memory:
        prompt_parts.append(f"""
📚 用戶長期記憶（跨會話記憶）：
{ltm_memory}
""")
    
    # 4. 短期記憶（STM）- 新增的對話上下文
    if stm_context:
        prompt_parts.append(f"""
💬 當前會話記憶（最近對話）：
{stm_context}

⚠️ 重要：基於上面的對話歷史，避免重複問已經回答過的問題！
""")
    
    # 5. 知識庫
    if kb_text:
        prompt_parts.append(f"""
📖 短影音知識庫：
{kb_text}
""")
    
    return "\n".join(prompt_parts)


def format_memory_for_display(memory_data: dict) -> str:
    """
    格式化記憶資料用於顯示
    
    Args:
        memory_data: {
            "stm": {...},  # 短期記憶
            "ltm": {...}   # 長期記憶
        }
    
    Returns:
        格式化的記憶摘要
    """
    parts = []
    
    # STM 摘要
    if memory_data.get("stm"):
        stm = memory_data["stm"]
        turns_count = len(stm.get("recent_turns", []))
        parts.append(f"💬 短期記憶：最近 {turns_count} 輪對話")
        if stm.get("last_summary"):
            parts.append(f"   摘要：{stm['last_summary'][:100]}...")
    
    # LTM 摘要
    if memory_data.get("ltm"):
        ltm = memory_data["ltm"]
        parts.append(f"📚 長期記憶：")
        if ltm.get("preferences"):
            parts.append(f"   偏好：{len(ltm['preferences'])} 項")
        if ltm.get("summaries"):
            parts.append(f"   對話記錄：{len(ltm['summaries'])} 筆")
        if ltm.get("generations"):
            parts.append(f"   生成記錄：{len(ltm['generations'])} 筆")
    
    return "\n".join(parts) if parts else "無記憶資料"

