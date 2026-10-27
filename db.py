from pymongo import MongoClient

client = MongoClient(
    "mongodb://localhost:27017",
    serverSelectionTimeoutMS=5000
)

db = client["receipes_db"]
recipes = db["recipes"]