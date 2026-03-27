from pymongo import MongoClient

c = MongoClient("mongodb://127.0.0.1:27017")
db = c["darkpulse"]

pipeline = [{"$group": {"_id": "$source", "count": {"$sum": 1}}}]
print("=== articles collection ===")
for doc in db.articles.aggregate(pipeline):
    print(f"  {doc['_id']}: {doc['count']}")
print(f"  TOTAL: {db.articles.count_documents({})}")

print()
print("=== redis_kv_store (raw crawl data) ===")
total = db.redis_kv_store.count_documents({})
print(f"  TOTAL keys: {total}")
for doc in db.redis_kv_store.find({}, {"_id": 0, "key": 1}).limit(15):
    print(f"  key: {doc.get('key', '?')}")
