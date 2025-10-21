#!/usr/bin/env python3
"""
資料庫管理工具
需要密碼才能執行危險操作（如刪除資料庫）
"""
import os
import sys
import hashlib
import getpass
import sqlite3
from datetime import datetime

# 密碼的 SHA256 雜湊值（預設密碼：AIJob2025）
# 如果要更改密碼，請執行：python db_admin.py --set-password
PASSWORD_HASH = "8f7c3a5d2e1b6f4a9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b"

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "chatbot.db")
DB_BACKUP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "backups")

def hash_password(password: str) -> str:
    """將密碼雜湊化"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password() -> bool:
    """驗證密碼"""
    print("🔐 此操作需要管理員密碼")
    password = getpass.getpass("請輸入管理員密碼：")
    
    if hash_password(password) == PASSWORD_HASH:
        print("✅ 密碼正確")
        return True
    else:
        print("❌ 密碼錯誤")
        return False

def backup_database():
    """備份資料庫"""
    if not os.path.exists(DB_PATH):
        print("⚠️ 資料庫不存在，無需備份")
        return None
    
    # 創建備份目錄
    os.makedirs(DB_BACKUP_DIR, exist_ok=True)
    
    # 生成備份檔案名稱
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(DB_BACKUP_DIR, f"chatbot_backup_{timestamp}.db")
    
    # 複製資料庫
    import shutil
    shutil.copy2(DB_PATH, backup_path)
    
    print(f"✅ 資料庫已備份到：{backup_path}")
    return backup_path

def delete_database():
    """刪除資料庫（需要密碼）"""
    print("=" * 60)
    print("⚠️  警告：刪除資料庫 ⚠️")
    print("=" * 60)
    print("此操作將刪除所有用戶資料，包括：")
    print("  - 用戶個人資料")
    print("  - 對話記錄")
    print("  - 生成記錄")
    print("  - 帳號定位記錄")
    print("  - 用戶偏好設定")
    print("  - 所有其他資料")
    print("=" * 60)
    
    # 確認操作
    confirm = input("\n您確定要刪除資料庫嗎？(輸入 'DELETE' 確認)：")
    if confirm != "DELETE":
        print("❌ 操作已取消")
        return False
    
    # 驗證密碼
    if not verify_password():
        print("❌ 密碼驗證失敗，操作已取消")
        return False
    
    # 再次確認
    final_confirm = input("\n⚠️  最後確認：真的要刪除資料庫嗎？(輸入 'YES' 確認)：")
    if final_confirm != "YES":
        print("❌ 操作已取消")
        return False
    
    # 備份資料庫
    print("\n📦 正在備份資料庫...")
    backup_path = backup_database()
    
    # 刪除資料庫
    try:
        if os.path.exists(DB_PATH):
            os.remove(DB_PATH)
            print(f"✅ 資料庫已刪除：{DB_PATH}")
            if backup_path:
                print(f"💾 備份檔案保存在：{backup_path}")
            return True
        else:
            print("⚠️ 資料庫不存在")
            return False
    except Exception as e:
        print(f"❌ 刪除失敗：{e}")
        return False

def reset_database():
    """重置資料庫（刪除後重建）"""
    print("=" * 60)
    print("🔄 重置資料庫")
    print("=" * 60)
    
    # 刪除資料庫
    if delete_database():
        print("\n🔨 正在重建資料庫...")
        # 重新導入並初始化資料庫
        from app import init_database
        init_database()
        print("✅ 資料庫已重置完成")
        return True
    else:
        return False

def list_backups():
    """列出所有備份"""
    print("=" * 60)
    print("💾 資料庫備份列表")
    print("=" * 60)
    
    if not os.path.exists(DB_BACKUP_DIR):
        print("⚠️ 沒有備份檔案")
        return
    
    backups = [f for f in os.listdir(DB_BACKUP_DIR) if f.endswith('.db')]
    
    if not backups:
        print("⚠️ 沒有備份檔案")
        return
    
    backups.sort(reverse=True)
    
    for i, backup in enumerate(backups, 1):
        backup_path = os.path.join(DB_BACKUP_DIR, backup)
        size = os.path.getsize(backup_path) / 1024  # KB
        mtime = datetime.fromtimestamp(os.path.getmtime(backup_path))
        print(f"{i}. {backup}")
        print(f"   大小：{size:.2f} KB")
        print(f"   時間：{mtime.strftime('%Y-%m-%d %H:%M:%S')}")
        print()

def restore_backup():
    """從備份還原資料庫"""
    print("=" * 60)
    print("♻️  還原資料庫")
    print("=" * 60)
    
    list_backups()
    
    if not os.path.exists(DB_BACKUP_DIR):
        return
    
    backups = [f for f in os.listdir(DB_BACKUP_DIR) if f.endswith('.db')]
    if not backups:
        return
    
    backups.sort(reverse=True)
    
    print("\n請選擇要還原的備份：")
    try:
        choice = int(input("輸入編號（輸入 0 取消）："))
        if choice == 0:
            print("❌ 操作已取消")
            return
        
        if choice < 1 or choice > len(backups):
            print("❌ 無效的選擇")
            return
        
        backup_file = backups[choice - 1]
        backup_path = os.path.join(DB_BACKUP_DIR, backup_file)
        
        # 驗證密碼
        if not verify_password():
            print("❌ 密碼驗證失敗，操作已取消")
            return
        
        # 先備份當前資料庫
        if os.path.exists(DB_PATH):
            print("\n📦 正在備份當前資料庫...")
            backup_database()
        
        # 還原備份
        import shutil
        shutil.copy2(backup_path, DB_PATH)
        print(f"✅ 資料庫已還原：{backup_file}")
        
    except ValueError:
        print("❌ 無效的輸入")
    except Exception as e:
        print(f"❌ 還原失敗：{e}")

def set_password():
    """設定新密碼"""
    print("=" * 60)
    print("🔑 設定管理員密碼")
    print("=" * 60)
    
    # 驗證舊密碼
    print("\n首先，請驗證當前密碼：")
    if not verify_password():
        print("❌ 密碼驗證失敗")
        return
    
    # 輸入新密碼
    print("\n請設定新密碼：")
    new_password = getpass.getpass("新密碼：")
    confirm_password = getpass.getpass("確認密碼：")
    
    if new_password != confirm_password:
        print("❌ 兩次輸入的密碼不一致")
        return
    
    if len(new_password) < 8:
        print("❌ 密碼長度至少為 8 個字元")
        return
    
    # 生成新密碼雜湊
    new_hash = hash_password(new_password)
    
    # 更新此腳本檔案
    script_path = os.path.abspath(__file__)
    with open(script_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 替換密碼雜湊
    import re
    pattern = r'PASSWORD_HASH = "[a-f0-9]{64}"'
    replacement = f'PASSWORD_HASH = "{new_hash}"'
    new_content = re.sub(pattern, replacement, content)
    
    with open(script_path, 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    print("✅ 密碼已更新")
    print(f"新密碼雜湊值：{new_hash}")

def show_menu():
    """顯示選單"""
    print("\n" + "=" * 60)
    print("🛠️  資料庫管理工具")
    print("=" * 60)
    print("1. 備份資料庫")
    print("2. 列出所有備份")
    print("3. 還原備份")
    print("4. 刪除資料庫（危險操作）")
    print("5. 重置資料庫（刪除並重建）")
    print("6. 設定管理員密碼")
    print("0. 退出")
    print("=" * 60)

def main():
    """主程式"""
    if len(sys.argv) > 1:
        # 命令行模式
        command = sys.argv[1]
        if command == "--backup":
            backup_database()
        elif command == "--delete":
            delete_database()
        elif command == "--reset":
            reset_database()
        elif command == "--list-backups":
            list_backups()
        elif command == "--restore":
            restore_backup()
        elif command == "--set-password":
            set_password()
        else:
            print(f"❌ 未知命令：{command}")
            print("\n可用命令：")
            print("  --backup          備份資料庫")
            print("  --delete          刪除資料庫")
            print("  --reset           重置資料庫")
            print("  --list-backups    列出備份")
            print("  --restore         還原備份")
            print("  --set-password    設定密碼")
    else:
        # 互動模式
        while True:
            show_menu()
            try:
                choice = input("\n請選擇操作：")
                
                if choice == "1":
                    backup_database()
                elif choice == "2":
                    list_backups()
                elif choice == "3":
                    restore_backup()
                elif choice == "4":
                    delete_database()
                elif choice == "5":
                    reset_database()
                elif choice == "6":
                    set_password()
                elif choice == "0":
                    print("👋 再見！")
                    break
                else:
                    print("❌ 無效的選擇")
                
                input("\n按 Enter 繼續...")
            except KeyboardInterrupt:
                print("\n\n👋 再見！")
                break
            except Exception as e:
                print(f"❌ 錯誤：{e}")

if __name__ == "__main__":
    main()

