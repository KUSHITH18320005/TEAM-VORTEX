import asyncio
import os
import httpx

API_KEY = os.environ.get("GEMINI_API_KEY", "AQ.Ab8RN6LCPoZvW8LZdS7q1I6aw28FuUNgpXDX9sEh2C8T7KPa5w").strip("<> \r\n\t\"'")

async def main():
    models_to_test = ["gemini-2.5-flash", "gemini-flash-latest", "gemini-3.6-flash", "gemini-2.5-pro"]
    async with httpx.AsyncClient(timeout=30.0) as client:
        for m in models_to_test:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{m}:generateContent?key={API_KEY}"
            payload = {
                "contents": [{"role": "user", "parts": [{"text": "You are Maddy SOC Copilot. Reply in 1 sentence: What is your status?"}]}],
                "generationConfig": {"temperature": 0.1, "maxOutputTokens": 60}
            }
            try:
                res = await client.post(url, json=payload)
                print(f"Model {m}: Status {res.status_code}")
                if res.status_code == 200:
                    data = res.json()
                    text = "".join(p.get("text", "") for p in data["candidates"][0]["content"]["parts"])
                    print(f"  -> SUCCESS ({m}): {text.strip()}")
                else:
                    print(f"  -> Error: {res.text[:200]}")
            except Exception as e:
                print(f"  -> Exception: {e}")

if __name__ == "__main__":
    asyncio.run(main())
