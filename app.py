import pyaes
from base64 import b64decode, b64encode
import json
import requests


AES_KEY = b"eECHALLAN@JSON$#"

def aes_ecb_decrypt(enc_b64: str) -> str:
    aes = pyaes.AESModeOfOperationECB(AES_KEY)
    raw = b64decode(enc_b64)

    decrypted = b""
    for i in range(0, len(raw), 16):
        block = raw[i:i+16]
        decrypted += aes.decrypt(block)

    pad = decrypted[-1]
    return decrypted[:-pad].decode("utf-8")


def aes_ecb_encrypt(plaintext: str) -> str:
    aes = pyaes.AESModeOfOperationECB(AES_KEY)
    data = plaintext.encode("utf-8")


    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len] * pad_len)

    encrypted = b""
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        encrypted += aes.encrypt(block)

    return b64encode(encrypted).decode("utf-8")


BASE_URL = "https://echallan.parivahan.gov.in/api/get-rc-offence-info"

HEADERS_TEMPLATE = {
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 15; 23124RN87I Build/AP3A.240905.015.A2)",
    "Connection": "Keep-Alive",
    "Accept": "application/json",
    "Accept-Encoding": "gzip",
    "Content-Type": "application/json",
    "Auth-Token": "YTAyNzEwNTliNjA4NGUzNzZjNGUxNGY4NTNmZTA2MTg6WDFzdE1RdFRoSVVzbkREZ0hITTFsQT09",
    "Content-Language": "en-US",
}

DEFAULT_PAYLOAD = {
    "device_user_id": "29592",
    "user_id": "329515",
    "token": "6a9ecf2963a6013eb8a44604ec5465a8",
    "IMEI": "AP3A.240905.015.A2",
    "state_code": "MP",
    "user_type": "CPU_DEPARTMENT",
    "is_traffic": 1,
    "mode": 1,
    "api_mode": "live",
    "is_chassis": 0,
}


def search_vehicle(reg_no: str, **overrides) -> dict:
    payload = {**DEFAULT_PAYLOAD, "reg_no": reg_no, **overrides}
    headers = {**HEADERS_TEMPLATE}

    try:
        resp = requests.post(
            BASE_URL,
            data=json.dumps(payload),
            headers=headers,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.RequestException as e:
        return {"success": False, "raw_response": None, "vehicle_details": None, "challan_details": None, "error": f"HTTP error: {e}"}
    except json.JSONDecodeError as e:
        return {"success": False, "raw_response": resp.text, "vehicle_details": None, "challan_details": None, "error": f"JSON decode error: {e}"}

    # Check API status
    if data.get("status") != 200:
        return {
            "success": False,
            "raw_response": data,
            "vehicle_details": None,
            "challan_details": None,
            "error": data.get("message", "Unknown API error"),
        }

    result = data.get("result", {})

    vehicle_details = None
    if enc_vehicle := result.get("vehicle_details"):
        try:
            vehicle_details = json.loads(aes_ecb_decrypt(enc_vehicle))
        except Exception as e:
            vehicle_details = {"__error__": f"Failed to decrypt vehicle_details: {e}"}

    challan_details = None
    if enc_challan := result.get("challan_details"):
        try:
            challan_details = json.loads(aes_ecb_decrypt(enc_challan))
        except Exception as e:
            challan_details = {"__error__": f"Failed to decrypt challan_details: {e}"}

    return {
        "success": True,
        "raw_response": data,
        "vehicle_details": vehicle_details,
        "challan_details": challan_details,
        "error": None,
    }


def encrypt_for_api(plaintext: str) -> str:
    return aes_ecb_encrypt(plaintext)

if __name__ == "__main__":
    import sys

    reg = sys.argv[1] if len(sys.argv) > 1 else "MH29SY6188"

    print(f"\n🔍 Searching vehicle: {reg}\n")
    result = search_vehicle(reg)

    if result["success"]:
        print("✅ API Status:", result["raw_response"].get("message"))
        print()

        if result["vehicle_details"]:
            print("🚗 Vehicle Details (decrypted):")
            print(json.dumps(result["vehicle_details"], indent=2, ensure_ascii=False))
        else:
            print("🚗 No vehicle details returned.")

        print()

        if result["challan_details"]:
            print("📋 Challan Details (decrypted):")
            print(json.dumps(result["challan_details"], indent=2, ensure_ascii=False))
        else:
            print("📋 No challan details returned.")
    else:
        print("❌ Error:", result["error"])
        if result["raw_response"]:
            print("Raw response:", result["raw_response"])
