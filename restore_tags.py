import json
from pathlib import Path
from db import recipes

# Read the recipes containing the restored tags.
file_path = Path(__file__).parent / "recipes_110_with_tags.json"

with file_path.open(encoding="utf-8") as file:
    records = json.load(file)

matched = 0
updated = 0

# Update only tags, preserving all other recipe fields and reviews.
for recipe in records:
    result = recipes.update_one(
        {"recipe_id": recipe["recipe_id"]},
        {"$set": {"tags": recipe["tags"]}}
    )

    matched += result.matched_count
    updated += result.modified_count

print("Recipes matched:", matched)
print("Recipes updated:", updated)