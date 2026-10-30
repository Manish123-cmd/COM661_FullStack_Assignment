from flask import Flask, jsonify, request, g
from bson import ObjectId
from db import recipes, users
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from pathlib import Path
import secrets

app = Flask(__name__)


# Create a secret key on the first run and reuse it on later runs.
secret_file = Path(__file__).parent / ".jwt_secret"

if not secret_file.exists():
    secret_file.write_text(secrets.token_hex(32), encoding="utf-8")

app.config["JWT_SECRET_KEY"] = secret_file.read_text(
    encoding="utf-8"
).strip()

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


# Check the token and find the logged-in user.
def jwt_required(func):
    @wraps(func)
    def jwt_required_wrapper(*args, **kwargs):
        authorization = request.headers.get("Authorization", "")

        if not authorization.startswith("Bearer "):
            return jsonify({"message": "Bearer token is required"}), 401

        token = authorization[7:].strip()

        try:
            data = jwt.decode(
                token,
                app.config["JWT_SECRET_KEY"],
                algorithms=["HS256"],
                options={"require": ["sub", "exp"]}
            )
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Token is invalid"}), 401

        # Check that the token contains a valid MongoDB user ID.
        if not ObjectId.is_valid(data["sub"]):
            return jsonify({"message": "Token is invalid"}), 401

        user = users.find_one({"_id": ObjectId(data["sub"])})

        if user is None:
            return jsonify({"message": "User not found"}), 401

        # Make the account available to the protected function.
        g.current_user = user

        return func(*args, **kwargs)

    return jwt_required_wrapper

# Allow access only to a logged-in administrator.
def admin_required(func):
    @wraps(func)
    def admin_required_wrapper(*args, **kwargs):
        if g.current_user.get("role") != "admin":
            return jsonify({"message": "Admin access required"}), 403

        return func(*args, **kwargs)

    return admin_required_wrapper

# Show the account identified by the login token.
@app.route("/auth/check", methods=["GET"])
@jwt_required
def check_login():
    return jsonify({
        "message": "Token is valid",
        "username": g.current_user["username"],
        "role": g.current_user["role"]
    }), 200

# Let an administrator view recipes using the existing search and pagination.
@app.route("/admin/recipes", methods=["GET"])
@jwt_required
@admin_required
def get_admin_recipes():
    return get_recipes()


# Let a logged-in user view their own account details.
@app.route("/user/profile", methods=["GET"])
@jwt_required
def get_user_profile():
    return jsonify({
        "user_id": str(g.current_user["_id"]),
        "username": g.current_user["username"],
        "role": g.current_user["role"]
    }), 200

# Check the username and password, then create a login token.
@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"message": "A JSON object is required"}), 400

    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({"message": "Username and password are required"}), 400

    user = users.find_one({"username": username.strip()})

    if user is None or not check_password_hash(user["password_hash"], password):
        return jsonify({"message": "Invalid username or password"}), 401

    token = jwt.encode(
        {
            "sub": str(user["_id"]),
            "exp": datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(minutes=30)
        },
        app.config["JWT_SECRET_KEY"],
        algorithm="HS256"
    )

    return jsonify({
        "message": "Login successful",
        "username": user["username"],
        "role": user["role"],
        "token": token
    }), 200

# Allow an administrator to create a recipe.
@app.route("/admin/recipes", methods=["POST"])
@jwt_required
@admin_required
def add_recipe():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"message": "A JSON object is required"}), 400

    recipe_id = data.get("recipe_id")
    name = data.get("name")
    minutes = data.get("minutes")

    if type(recipe_id) is not int or recipe_id < 1:
        return jsonify({"message": "recipe_id must be a positive integer"}), 400

    if not isinstance(name, str) or not name.strip():
        return jsonify({"message": "Recipe name is required"}), 400

    if type(minutes) is not int or minutes < 0:
        return jsonify({"message": "minutes must be a non-negative integer"}), 400

    # Check that these fields contain lists of non-empty strings.
    for field in ["ingredients", "steps", "tags"]:
        value = data.get(field)

        if not isinstance(value, list):
            return jsonify({"message": f"{field} must be a list"}), 400

        if field != "tags" and not value:
            return jsonify({"message": f"{field} cannot be empty"}), 400

        for item in value:
            if not isinstance(item, str) or not item.strip():
                return jsonify({
                    "message": f"{field} must contain non-empty strings"
                }), 400

    if not isinstance(data.get("nutrition"), dict):
        return jsonify({"message": "nutrition must be a JSON object"}), 400

    if recipes.find_one({"recipe_id": recipe_id}):
        return jsonify({"message": "Recipe ID already exists"}), 409

    recipe = {
        "recipe_id": recipe_id,
        "name": name.strip(),
        "minutes": minutes,
        "ingredients": data["ingredients"],
        "steps": data["steps"],
        "tags": data["tags"],
        "nutrition": data["nutrition"],
        "reviews": []
    }

    recipes.insert_one(recipe)

    return jsonify({
        "message": "Recipe created successfully",
        "recipe_id": recipe_id
    }), 201

# Allow an administrator to update a recipe's details.
@app.route("/admin/recipes/<int:recipe_id>", methods=["PUT"])
@jwt_required
@admin_required
def update_recipe(recipe_id):
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"message": "A JSON object is required"}), 400

    name = data.get("name")
    minutes = data.get("minutes")

    if not isinstance(name, str) or not name.strip():
        return jsonify({"message": "Recipe name is required"}), 400

    if type(minutes) is not int or minutes < 0:
        return jsonify({"message": "minutes must be a non-negative integer"}), 400

    # Check that these fields contain lists of non-empty strings.
    for field in ["ingredients", "steps", "tags"]:
        value = data.get(field)

        if not isinstance(value, list):
            return jsonify({"message": f"{field} must be a list"}), 400

        if field != "tags" and not value:
            return jsonify({"message": f"{field} cannot be empty"}), 400

        for item in value:
            if not isinstance(item, str) or not item.strip():
                return jsonify({
                    "message": f"{field} must contain non-empty strings"
                }), 400

    if not isinstance(data.get("nutrition"), dict):
        return jsonify({"message": "nutrition must be a JSON object"}), 400

    result = recipes.update_one(
        {"recipe_id": recipe_id},
        {
            "$set": {
                "name": name.strip(),
                "minutes": minutes,
                "ingredients": data["ingredients"],
                "steps": data["steps"],
                "tags": data["tags"],
                "nutrition": data["nutrition"]
            }
        }
    )

    if result.matched_count == 0:
        return jsonify({"message": "Recipe not found"}), 404

    return jsonify({"message": "Recipe updated successfully"}), 200

# Allow an administrator to delete a recipe and its embedded reviews.
@app.route("/admin/recipes/<int:recipe_id>", methods=["DELETE"])
@jwt_required
@admin_required
def delete_recipe(recipe_id):
    result = recipes.delete_one({"recipe_id": recipe_id})

    if result.deleted_count == 0:
        return jsonify({"message": "Recipe not found"}), 404

    return jsonify({"message": "Recipe deleted successfully"}), 200

# Let a logged-in user add a review to a recipe.
@app.route("/user/recipes/<int:recipe_id>/reviews", methods=["POST"])
@jwt_required
def add_review(recipe_id):
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"message": "A JSON object is required"}), 400

    rating = data.get("rating")
    comment = data.get("comment")

    if type(rating) is not int or rating < 1 or rating > 5:
        return jsonify({
            "message": "Rating must be a whole number between 1 and 5"
        }), 400

    if not isinstance(comment, str) or not comment.strip():
        return jsonify({"message": "Comment is required"}), 400

    # Take the author's identity from the verified login token.
    review = {
        "review_id": str(ObjectId()),
        "user_id": str(g.current_user["_id"]),
        "username": g.current_user["username"],
        "rating": rating,
        "comment": comment.strip(),
        "date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source": "application"
    }

    result = recipes.update_one(
        {"recipe_id": recipe_id},
        {"$push": {"reviews": review}}
    )

    if result.matched_count == 0:
        return jsonify({"message": "Recipe not found"}), 404

    return jsonify({
        "message": "Review added successfully",
        "recipe_id": recipe_id,
        "review": review
    }), 201

    
# Start the Flask development server on port 5003.
if __name__ == "__main__":
    app.run(debug=True, port=5003)