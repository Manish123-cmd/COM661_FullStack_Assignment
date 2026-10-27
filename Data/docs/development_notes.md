### GET /guest/recipes

- Connects to receipes_db.recipes in MongoDB.
- find({}) retrieves recipes without filtering.
- {"_id": 0} excludes MongoDB's ObjectId from the response.
- limit(10) restricts the response to 10 recipes.
- list() collects the query results.
- jsonify() sends them as JSON.
- HTTP 200 indicates a successful request.

Video explanation:
"This endpoint retrieves up to 10 recipes from MongoDB.
I limited the response size to keep it manageable.
Pagination will let users request the remaining recipes.
I added validated pagination using skip and limit. Sorting by recipe ID keeps the ordering consistent, and the response includes the total records and pages.