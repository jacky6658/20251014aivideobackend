#!/usr/bin/env python3
"""
測試 ECPay Webhook 端點
用於驗證 webhook 是否正常運作
"""

import requests
import json
from datetime import datetime

# 測試配置
WEBHOOK_URL = "https://aivideobackend.zeabur.app/api/payment/webhook"
BACKEND_BASE = "https://aivideobackend.zeabur.app"

def test_webhook_endpoint():
    """測試 webhook 端點是否可訪問"""
    print("=" * 60)
    print("測試 1: 檢查 Webhook 端點是否可訪問")
    print("=" * 60)
    
    try:
        # 發送一個簡單的 POST 請求（不包含 ECPay 參數，應該會被拒絕，但至少可以確認端點存在）
        response = requests.post(
            WEBHOOK_URL,
            data={},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10
        )
        
        print(f"✅ Webhook 端點可訪問")
        print(f"   狀態碼: {response.status_code}")
        print(f"   回應: {response.text[:200]}")
        
        if response.status_code == 200:
            print("   ⚠️  注意：端點返回 200，但應該返回 0|FAIL（因為沒有有效的 ECPay 參數）")
        elif response.text.strip() == "0|FAIL":
            print("   ✅ 端點正確拒絕了無效請求")
        
        return True
    except requests.exceptions.RequestException as e:
        print(f"❌ 無法訪問 Webhook 端點: {e}")
        return False

def test_backend_health():
    """測試後端服務是否正常運行"""
    print("\n" + "=" * 60)
    print("測試 2: 檢查後端服務健康狀態")
    print("=" * 60)
    
    try:
        # 嘗試訪問根路徑或健康檢查端點
        response = requests.get(f"{BACKEND_BASE}/", timeout=10)
        print(f"✅ 後端服務正常運行")
        print(f"   狀態碼: {response.status_code}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"❌ 後端服務無法訪問: {e}")
        return False

def check_environment_variables():
    """檢查環境變數設定（僅提供說明）"""
    print("\n" + "=" * 60)
    print("測試 3: 環境變數檢查（需要在 Zeabur 後台確認）")
    print("=" * 60)
    
    required_vars = [
        "ECPAY_MERCHANT_ID",
        "ECPAY_HASH_KEY",
        "ECPAY_HASH_IV",
        "ECPAY_NOTIFY_URL",
        "ECPAY_RETURN_URL",
        "ECPAY_IP_WHITELIST"
    ]
    
    print("請在 Zeabur 後台確認以下環境變數已設定：")
    for var in required_vars:
        print(f"   - {var}")
    
    print("\n預期值：")
    print(f"   ECPAY_NOTIFY_URL=https://aivideobackend.zeabur.app/api/payment/webhook")
    print(f"   ECPAY_RETURN_URL=https://reelmind.aijob.com.tw/payment-result.html")
    print(f"   ECPAY_IP_WHITELIST=210.200.4.0/24,210.200.5.0/24")

def explain_webhook_flow():
    """說明 Webhook 通知流程"""
    print("\n" + "=" * 60)
    print("Webhook 通知流程說明")
    print("=" * 60)
    
    print("""
當您使用 API 動態建立訂單（/api/payment/checkout）時：

1. ✅ 後端會在建立訂單時自動設定 ReturnURL
   - ReturnURL = https://aivideobackend.zeabur.app/api/payment/webhook
   - 這個 URL 會在每次建立訂單時自動包含在請求參數中

2. ✅ 不需要在 ECPay 後台設定「伺服器端回傳網址」
   - 因為 ReturnURL 是在每次訂單請求中動態指定的
   - ECPay 會根據訂單請求中的 ReturnURL 參數來發送 Webhook

3. ✅ 付款完成後，ECPay 會自動發送通知
   - ECPay 會發送 POST 請求到 https://aivideobackend.zeabur.app/api/payment/webhook
   - 後端會驗證 IP 白名單和簽章
   - 如果驗證通過，會更新訂單狀態和訂閱狀態

4. ⚠️  關於「返回商店按鈕」設定
   - 您在綠界後台設定的「返回商店按鈕」只影響固定連結
   - 對於 API 動態建立訂單，OrderResultURL 是在每次訂單請求中指定的
   - 所以即使沒有在後台設定，也不會影響 Webhook 通知
    """)

def diagnose_payment_error():
    """診斷「商店尚未提供任何付款方式」錯誤"""
    print("\n" + "=" * 60)
    print("診斷：交易失敗「商店尚未提供任何付款方式」")
    print("=" * 60)
    
    print("""
可能原因：

1. ❌ ChoosePayment 設定問題
   - 目前後端設定為 "Credit"（信用卡）
   - 如果您的 ECPay 商店沒有開通信用卡付款，會出現此錯誤
   - 解決方法：在 ECPay 後台確認信用卡付款是否已開通

2. ❌ 測試/生產環境混用
   - 測試環境的 MerchantID/HashKey/HashIV 與生產環境不同
   - 如果使用測試環境的設定，但連接到生產環境的 API，會出現此錯誤
   - 解決方法：確認環境變數是否與當前使用的 ECPay 環境一致

3. ❌ Hash Key/IV 設定錯誤
   - Hash Key 或 Hash IV 設定錯誤會導致簽章驗證失敗
   - ECPay 可能會返回「商店尚未提供任何付款方式」錯誤
   - 解決方法：確認 ECPAY_HASH_KEY 和 ECPAY_HASH_IV 是否正確

4. ❌ MerchantID 設定錯誤
   - MerchantID 設定錯誤會導致 ECPay 無法識別商店
   - 解決方法：確認 ECPAY_MERCHANT_ID 是否正確

建議檢查步驟：
1. 確認 ECPay 後台是否已開通信用卡付款
2. 確認環境變數是否與當前 ECPay 環境一致（測試/生產）
3. 確認 Hash Key/IV 和 MerchantID 是否正確
4. 查看後端日誌，確認是否有簽章驗證錯誤
    """)

def main():
    print("\n" + "=" * 60)
    print("ECPay Webhook 測試工具")
    print("=" * 60)
    print(f"測試時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Webhook URL: {WEBHOOK_URL}")
    print()
    
    # 執行測試
    test_webhook_endpoint()
    test_backend_health()
    check_environment_variables()
    explain_webhook_flow()
    diagnose_payment_error()
    
    print("\n" + "=" * 60)
    print("測試完成")
    print("=" * 60)
    print("""
下一步：
1. 確認環境變數設定正確
2. 確認 ECPay 後台已開通信用卡付款
3. 嘗試建立一個測試訂單，查看後端日誌
4. 如果問題持續，請聯繫 ECPay 客服確認商店設定
    """)

if __name__ == "__main__":
    main()

