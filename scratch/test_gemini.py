import asyncio
import os
import httpx

API_KEY = os.environ.get("GEMINI_API_KEY", "AQ.Ab8RN6LCPoZvW8LZdS7q1I6aw28FuUNgpXDX9sEh2C8T7KPa5w").strip("<> \r\n\t\"'")

async def main():
    print(f"Testing Gemini API with key: {API_KEY[:6]}...{API_KEY[-4:]}")
    models = ["gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.5-pro", "gemini-2.5-flash"]
    async with httpx.AsyncClient(timeout=15.0) as client:
        for m in models:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{m}:generateContent?key={API_KEY}"
            payload = {
                "contents": [{"role": "user", "parts": [{"text": "Hello, respond with ONE short sentence confirming you are Gemini."}]}],
                "generationConfig": {"temperature": 0.1, "maxOutputTokens": 100}
            }
            try:
                res = await client.post(url, json=payload)
                print(f"Model {m}: Status {res.status_code}")
                if res.status_code == 200:
                    data = res.json()
                    text = "".join(p.get("text", "") for p in data["candidates"][0]["content"]["parts"])
                    print(f"  -> Response: {text.strip()}")
                else:
                    print(f"  -> Error: {res.text[:200]}")
            except Exception as e:
                print(f"  -> Exception on {m}: {e}")

if __name__ == "__main__":
    asyncio.run(main())
