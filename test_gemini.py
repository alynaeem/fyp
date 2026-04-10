import os
from pathlib import Path

from dotenv import load_dotenv
from google import genai

load_dotenv(Path(__file__).resolve().parent / ".env")

api_key = os.getenv("GEMINI_API_KEY", "").strip()
if not api_key:
    raise SystemExit("GEMINI_API_KEY is not set in .env")

client = genai.Client(api_key=api_key)

try:
    print("Listing models...")
    for model in client.models.list():
        print(f"Model: {model.name} (Methods: {model.supported_methods})")
except Exception as e:
    print(f"Listing failed: {e}")

try:
    print("\nTesting gemini-1.5-flash at v1...")
    v1_client = genai.Client(api_key=api_key, http_options={'api_version': 'v1'})
    response = v1_client.models.generate_content(
        model='gemini-1.5-flash',
        contents="Say hello"
    )
    print(f"Success (v1): {response.text}")
except Exception as e:
    print(f"Failed v1: {e}")
