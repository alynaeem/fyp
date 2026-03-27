from pymongo import MongoClient

c = MongoClient("mongodb://127.0.0.1:27017")
db = c["darkpulse"]

print("=== redis_kv_store sample ===")
for doc in db.redis_kv_store.find().limit(3):
    keys = list(doc.keys())
    print(f"  Document keys: {keys}")
    for k, v in doc.items():
        if k == "_id":
            continue
        val_str = str(v)[:200]
        print(f"    {k}: {val_str}")
    print()

print("=== articles sample ===")
for doc in db.articles.find().limit(2):
    keys = list(doc.keys())
    print(f"  Document keys: {keys}")
    for k, v in doc.items():
        if k == "_id":
            continue
        val_str = str(v)[:200]
        print(f"    {k}: {val_str}")
    print()

# Count redis_kv_store by looking at first part of value or structure
import json
print("=== redis_kv_store: distinct structures ===")
sample = db.redis_kv_store.find_one()
if sample:
    for k, v in sample.items():
        print(f"  {k}: type={type(v).__name__}, value={str(v)[:300]}")
