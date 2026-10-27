from flask import Flask, jsonify, request
from db import recipes, users
from werkzeug.security import generate_password_hash

app = Flask(__name__)


# Get a paginated list of recipes, with an optional ingredient search.
@app.route("/guest/recipes", methods=["GET"])
def get_recipes():
    ingredient = request.args.get("ingredient", "").strip()

    try:
        page = int(request.args.get("page", 1))
        limit = int(request.args.get("limit", 10))
    except ValueError:
        return jsonify({
            "message": "page and limit must be whole numbers"
        }), 400

    if page < 1 or limit < 1 or limit > 50:
        return jsonify({
            "message": "page must be at least 1 and limit must be between 1 and 50"
        }), 400

    query = {}

    if ingredient:
        query["ingredients"] = {
            "$regex": ingredient,
            "$options": "i"
        }

    total = recipes.count_documents(query)

    records = list(
        recipes.find(query, {"_id": 0})
        .sort("recipe_id", 1)
        .skip((page - 1) * limit)
        .limit(limit)
    )

    return jsonify({
        "page": page,
        "limit": limit,
        "total": total,
        "recipes": records
    }), 200


# Get the full details of one recipe using its recipe ID.
@app.route("/guest/recipes/<int:recipe_id>", methods=["GET"])
def get_recipe(recipe_id):
    recipe = recipes.find_one(
        {"recipe_id": recipe_id},
        {"_id": 0}
    )

    if recipe is None:
        return jsonify({"message": "Recipe not found"}), 404

    return jsonify(recipe), 200


# Get the nested reviews belonging to one recipe.
@app.route("/guest/recipes/<int:recipe_id>/reviews", methods=["GET"])
def get_recipe_reviews(recipe_id):
    recipe = recipes.find_one(
        {"recipe_id": recipe_id},
        {"_id": 0, "reviews": 1}
    )

    if recipe is None:
        return jsonify({"message": "Recipe not found"}), 404

    return jsonify({
        "recipe_id": recipe_id,
        "reviews": recipe.get("reviews", [])
    }), 200


# Get one specific review belonging to a recipe.
@app.route(
    "/guest/recipes/<int:recipe_id>/reviews/<string:review_id>",
    methods=["GET"]
)
def get_one_review(recipe_id, review_id):
    recipe = recipes.find_one(
        {"recipe_id": recipe_id},
        {"_id": 0, "reviews": 1}
    )

    if recipe is None:
        return jsonify({"message": "Recipe not found"}), 404

    for review in recipe.get("reviews", []):
        if review.get("review_id") == review_id:
            return jsonify(review), 200

    return jsonify({"message": "Review not found"}), 404

# Register a new application user.
@app.route("/auth/register", methods=["POST"])
def register():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"message": "A JSON object is required"}), 400

    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not username.strip():
        return jsonify({"message": "Username is required"}), 400

    if not isinstance(password, str) or len(password) < 8:
        return jsonify({
            "message": "Password must be at least 8 characters"
        }), 400

    username = username.strip()

    if users.find_one({"username": username}):
        return jsonify({"message": "Username already exists"}), 409

    user = {
        "username": username,
        "password_hash": generate_password_hash(password),
        "role": "user"
    }

    users.insert_one(user)

    return jsonify({
        "message": "User registered successfully",
        "username": username,
        "role": "user"
    }), 201

# Start the Flask development server on port 5003.
if __name__ == "__main__":
    app.run(debug=True, port=5003)