from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
import jwt
import datetime
from bson.objectid import ObjectId # type: ignore
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import os
from dotenv import load_dotenv
import pytesseract
from PIL import Image
import io
import re
import json
import google.generativeai as genai

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app, supports_credentials=True)

# MongoDB connection
mongo_uri = os.getenv("MONGODB_URI")
client = MongoClient(mongo_uri)
db = client["smart_food_manager"]
users_collection = db["users"]
foods_collection = db["foods"]

# JWT Config
SECRET_KEY = os.getenv("SECRET_KEY", "112")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# Google Generative AI Config
# Config (works in v0.3.0+)
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
genai.configure(api_key=GOOGLE_API_KEY)  # type: ignore
model = genai.GenerativeModel("gemini-pro")  # type: ignore

# Set Tesseract path if provided
tesseract_path = os.getenv("Tesseract_PATH")
if tesseract_path:
    pytesseract.pytesseract.tesseract_cmd = tesseract_path

# Check for required environment variables
if __name__ == "__main__":
    required_env_vars = ['MONGODB_URI', 'GOOGLE_API_KEY']
    missing = [var for var in required_env_vars if not os.getenv(var)]
    if missing:
        raise EnvironmentError(f"Missing required env vars: {', '.join(missing)}")
    app.run(debug=True, port=5000)


# Helper function to serialize ObjectId
def serialize_object_id(obj):
    if isinstance(obj, dict):
        for k, v in list(obj.items()):
            if isinstance(v, ObjectId):
                obj[k] = str(v)
            elif isinstance(v, (dict, list)):
                serialize_object_id(v)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            if isinstance(v, ObjectId):
                obj[i] = str(v)
            elif isinstance(v, (dict, list)):
                serialize_object_id(v)
    return obj

# JWT token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]

        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            current_user = users_collection.find_one({"_id": ObjectId(data["user_id"])})
            if not current_user:
                return jsonify({'message': 'User not found'}), 401
        except:
            return jsonify({'message': 'Token is invalid'}), 401

        return f(current_user, *args, **kwargs)
    return decorated

# Routes
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json

    # Check for all required fields
    if not data or "email" not in data or "password" not in data or "name" not in data:
        return jsonify({"message": "Name, email, and password are required"}), 400

    # Check if user already exists
    if users_collection.find_one({"email": data["email"]}):
        return jsonify({"message": "User with this email already exists"}), 400
    
    # Create new user
    hashed_password = generate_password_hash(data["password"])
    user_id = users_collection.insert_one({
        "name": data["name"],
        "email": data["email"],
        "password": hashed_password,
        "created_at": datetime.datetime.utcnow()
    }).inserted_id
    
    # Generate token
    # In both register and login routes:
    token = jwt.encode({
        "user_id": str(user_id),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    }, SECRET_KEY, algorithm=ALGORITHM).encode('utf-8')  # Add .encode()
        
    # Get user without password
    user = users_collection.find_one({"_id": user_id}, {"password": 0})
    user = serialize_object_id(user)
    
    return jsonify({"token": token, "user": user}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json

    if not data or "email" not in data or "password" not in data:
        return jsonify({"message": "Email and password are required"}), 400

    # Find user
    user = users_collection.find_one({"email": data["email"]})
    
    if not user or not check_password_hash(user["password"], data["password"]):
        return jsonify({"message": "Invalid email or password"}), 401
    
    # Generate token
    token = jwt.encode({
        "user_id": str(user["_id"]),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    }, SECRET_KEY, algorithm=ALGORITHM).encode('utf-8')  # Add .encode()
    
    # Return user without password
    user.pop("password", None)
    user = serialize_object_id(user)
    
    return jsonify({"token": token, "user": user})

@app.route('/api/foods', methods=['GET'])
@token_required
def get_all_foods(current_user):
    user_foods = list(foods_collection.find({"userId": str(current_user["_id"])}))
    return jsonify({"foods": serialize_object_id(user_foods)})

@app.route('/api/foods/expiring/<int:days>', methods=['GET'])
@token_required
def get_expiring_foods(current_user, days):
    # Calculate the date X days from now
    expiry_date = datetime.datetime.now() + datetime.timedelta(days=days)
    
    # Find foods that expire before that date
    expiring_foods = list(foods_collection.find({
        "userId": str(current_user["_id"]),
        "expiryDate": {"$lte": expiry_date.strftime('%Y-%m-%d')}
    }))
    
    return jsonify({"foods": serialize_object_id(expiring_foods)})

@app.route('/api/foods', methods=['POST'])
@token_required
def add_food(current_user):
    data = request.json
    
    if not data or "name" not in data or "expiryDate" not in data:
        return jsonify({"message": "Name and expiryDate are required"}), 400

    food = {
        "userId": str(current_user["_id"]),
        "name": data["name"],
        "expiryDate": data["expiryDate"],
        "createdAt": datetime.datetime.utcnow().isoformat()
    }
    
    result = foods_collection.insert_one(food)
    food["_id"] = str(result.inserted_id)
    
    return jsonify({"food": food}), 201

@app.route('/api/foods/<food_id>', methods=['DELETE'])
@token_required
def delete_food(current_user, food_id):
    result = foods_collection.delete_one({
        "_id": ObjectId(food_id),
        "userId": str(current_user["_id"])
    })
    
    if result.deleted_count == 0:
        return jsonify({"message": "Food not found or not authorized"}), 404
    
    return jsonify({"message": "Food deleted successfully"})

@app.route('/api/ocr', methods=['POST'])
@token_required
def process_image_ocr(current_user):
    if 'image' not in request.files:
        return jsonify({"message": "No image provided"}), 400
    
    image_file = request.files['image']
    image = Image.open(io.BytesIO(image_file.read()))
    
    try:
        # Extract text from image
        extracted_text = pytesseract.image_to_string(image)
        return jsonify({"text": extracted_text})
    except Exception as e:
        return jsonify({"message": f"OCR processing error: {str(e)}"}), 500

@app.route('/api/recipes/generate', methods=['POST'])
@token_required
def generate_recipe_from_ingredients(current_user):
    data = request.get_json()
    if not data or 'ingredients' not in data:
        return jsonify({"message": "No ingredients provided"}), 400
    ingredients = data.get('ingredients', [])
    
    if not ingredients:
        return jsonify({"message": "No ingredients provided"}), 400
    
    try:
        ingredients_str = ", ".join(ingredients)
        prompt = f"""
        Create a recipe using some or all of these ingredients: {ingredients_str}.
        
        Format the response as a JSON object with the following structure:
        {{
            "title": "Recipe Title",
            "description": "A brief description of the dish",
            "ingredients": ["Ingredient 1", "Ingredient 2", ...],
            "instructions": ["Step 1", "Step 2", ...]
        }}
        
        Only include the JSON in your response, no other text.
        """
        
        response = model.generate_content(prompt)
        response_text = response.text
        
        # Clean up the response to extract just the JSON
        json_match = re.search(r'```json\s*(.*?)\s*```', response_text, re.DOTALL)
        if json_match:
            response_text = json_match.group(1)
        
        # Parse the response as JSON
        recipe_data = json.loads(response_text)
        
        return jsonify({"recipe": recipe_data})
    except Exception as e:
        print(f"Error generating recipe: {str(e)}")
        return jsonify({"message": f"Failed to generate recipe: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5000)
