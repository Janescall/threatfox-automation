import requests
import json
import time
import re  # 정규식 사용

# ThreatFox 최신 IOC 데이터 URL
THREATFOX_URL = "https://threatfox.abuse.ch/export/json/recent/"

# JSON 파일 저장 위치 (웹 서버 접근 가능하도록 설정)
RAW_OUTPUT_FILE = "C:\\Users\\jane00\\Desktop\\KISA\\threatfox_raw_data.json"
OUTPUT_FILE = "C:\\Users\\jane00\\Desktop\\KISA\\threatfox_cb_feed.json"

def clean_ip(ip_port):
    """ip:port 형식에서 IP만 추출"""
    return re.match(r"^([\d\.]+):\d+$", ip_port).group(1) if ":" in ip_port else ip_port

def fetch_threatfox_data():
    """ThreatFox에서 최신 IOC 데이터를 가져와 리스트로 변환"""
    try:
        response = requests.get(THREATFOX_URL)
        data = response.json()

        # 원본 데이터 전체 저장 (모든 데이터를 보존)
        with open(RAW_OUTPUT_FILE, "w") as raw_file:
            json.dump(data, raw_file, indent=4)
        print(f"✅ 원본 ThreatFox 데이터가 저장되었습니다: {RAW_OUTPUT_FILE}")

        if not isinstance(data, dict) or len(data) == 0:
            print("⚠️ ThreatFox 응답이 비어 있거나 예상과 다름.")
            return []

        iocs = set()

        # 숫자 키가 포함된 데이터 구조 처리
        for key, entries in data.items():
            if not isinstance(entries, list):  # 숫자 키 아래 리스트가 아닌 경우 스킵
                print(f"⚠️ 예상치 못한 데이터 구조 (키: {key}) → {entries}")
                continue

            for entry in entries:
                ioc_type = entry.get("ioc_type")
                ioc_value = entry.get("ioc_value")
                reference = entry.get("reference", "https://threatfox.abuse.ch")
                malware_printable = entry.get("malware_printable", "Unknown")
                score = entry.get("confidence_level", 50)  # 기본값 50 설정
                
                # URL 타입 제거
                if ioc_type == "url":
                    continue
                
                # ip:port 타입의 경우 포트 제거
                if ioc_type == "ip:port":
                    ioc_value = clean_ip(ioc_value)
                    ioc_type = "ip"  # Carbon Black은 "ip" 타입을 사용
                
                if ioc_type and ioc_value:
                    iocs.add((ioc_type, ioc_value, reference, malware_printable, score))

        return [{"type": t, "value": v, "reference": r, "malware_printable": g, "score": s} for t, v, r, g, s in iocs]

    except Exception as e:
        print(f"❌ JSON 처리 중 오류 발생: {str(e)}")
        return []

def generate_cb_feed(iocs):
    """Carbon Black EDR에 맞는 JSON 피드를 생성 (malware_printable 기준 그룹화)"""
    try:
        timestamp = int(time.time())
        reports = []
        malware_dict = {}

        for ioc in iocs:
            malware_printable = ioc["malware_printable"]
            ioc_type = ioc["type"]
            ioc_value = ioc["value"]
            reference = ioc["reference"]
            score = ioc["score"]

            if malware_printable not in malware_dict:
                malware_dict[malware_printable] = {
                    "id": f"threatfox-{malware_printable}",
                    "timestamp": timestamp,
                    "title": f"ThreatFox IOC - {malware_printable}",
                    "link": reference,
                    "score": score,
                    "iocs": {}
                }
            
            if ioc_type not in malware_dict[malware_printable]["iocs"]:
                malware_dict[malware_printable]["iocs"][ioc_type] = set()
            
            malware_dict[malware_printable]["iocs"][ioc_type].add(ioc_value)

        # Convert sets to lists
        for malware_printable in malware_dict:
            for ioc_type in malware_dict[malware_printable]["iocs"]:
                malware_dict[malware_printable]["iocs"][ioc_type] = list(malware_dict[malware_printable]["iocs"][ioc_type])
        
        reports = list(malware_dict.values())

        feed = {
            "feedinfo": {
                "name": "ThreatFox IOC Feed",
                "provider_url": "https://threatfox.abuse.ch",
                "summary": "ThreatFox에서 제공하는 최신 악성코드 IOC",
                "tech_data": "ThreatFox에서 제공하는 공개 위협 데이터",
                "category": "Open Source",
                "icon": "https://threatfox.abuse.ch/static/img/favicon.ico"
            },
            "reports": reports
        }

        with open(OUTPUT_FILE, "w") as f:
            json.dump(feed, f, indent=4)

        print(f"✅ ThreatFox IOC 피드가 저장되었습니다: {OUTPUT_FILE}")

    except Exception as e:
        print(f"❌ JSON 저장 중 오류 발생: {str(e)}")

if __name__ == "__main__":
    iocs = fetch_threatfox_data()
    if iocs:
        generate_cb_feed(iocs)
    else:
        print("⚠️ ThreatFox에서 가져온 IOC 데이터가 없습니다.")
