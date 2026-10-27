from flask import Flask, jsonify, request
from db import recipes

app = Flask(__name__)

@app.route("/guest/recipes", methods=["GET"])
def get_recipes():
    ingredient = request.args.get("ingredient", "").strip()

    query = {}

    if ingredient:
        query["ingredients"] = {
            "$regex": ingredient,
            "$options": "i"
        }

    records = list(
        recipes.find(query, {"_id": 0}).limit(10)
    )

    return jsonify(records), 200

@app.route("/guest/recipes/<int:recipe_id>", methods=["GET"])
def get_recipe(recipe_id):
    recipe = recipes.find_one(
        {"recipe_id": recipe_id},
        {"_id": 0}
    )

    if recipe is None:
        return jsonify({"message": "Recipe not found"}), 404

    return jsonify(recipe), 200

if __name__ == "__main__":
    app.run(debug=True, port=5003)