import asyncio
import os
import httpx

API_KEY = os.environ.get("GEMINI_API_KEY", "AQ.Ab8RN6LCPoZvW8LZdS7q1I6aw28FuUNgpXDX9sEh2C8T7KPa5w").strip("<> \r\n\t\"'")

async def main():
    async with httpx.AsyncClient(timeout=15.0) as client:
        # 1. List available models
        list_url = f"https://generativelanguage.googleapis.com/v1beta/models?key={API_KEY}"
        res = await client.get(list_url)
        print("ListModels Status:", res.status_code)
        if res.status_code == 200:
            data = res.json()
            models = data.get("models", [])
            print(f"Found {len(models)} models:")
            for m in models:
                name = m.get("name")
                methods = m.get("supportedGenerationMethods", [])
                if "generateContent" in methods:
                    print(f"  - {name} ({m.get('displayName')})")
        else:
            print("Error listing models:", res.text)

        # 2. Test candidate models
        test_candidates = ["gemini-3.6-flash", "gemini-3.0-flash", "gemini-2.5-flash", "gemini-2.0-flash", "gemini-2.0-flash-001", "gemini-pro"]
        for cand in test_candidates:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{cand}:generateContent?key={API_KEY}"
            payload = {
                "contents": [{"role": "user", "parts": [{"text": "Hello, respond with ONE short sentence confirming you are Gemini."}]}],
                "generationConfig": {"temperature": 0.1, "maxOutputTokens": 100}
            }
            res = await client.post(url, json=payload)
            print(f"Cand {cand}: Status {res.status_code}")
            if res.status_code == 200:
                data = res.json()
                text = "".join(p.get("text", "") for p in data["candidates"][0]["content"]["parts"])
                print(f"  -> SUCCESS: {text.strip()}")

if __name__ == "__main__":
    asyncio.run(main())
