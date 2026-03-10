import pymongo
from config import cfg

client = pymongo.MongoClient(cfg.mongo_uri, serverSelectionTimeoutMS=2000)
db = client[cfg.mongo_db]
for coll_name in db.list_collection_names():
    count = db[coll_name].count_documents({})
    print(f"Collection: {coll_name} - Count: {count}")
    
    if count > 0:
        doc = db[coll_name].find_one({})
        print(f"Sample from {coll_name}: {list(doc.keys())}")
