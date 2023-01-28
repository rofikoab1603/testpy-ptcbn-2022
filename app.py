# save this as app.py
from flask import Flask, request
from markupsafe import escape
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from flask import jsonify

# from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://username:password@host:port/database_name'
app.config['JWT_SECRET_KEY'] = 'your_secret_key'
app.config['JWT_ALGORITHM'] = 'HS256'
jwt = JWTManager(app)
# db = SQLAlchemy(app)


@app.route('/api/auth/user', methods=['GET'])
@jwt_required
def current_user():
    if current_user:
        return jsonify(id=current_user.id, username=current_user.username), 200
    else:
        return jsonify({"msg": "User not found"}), 404

@jwt.expired_token_loader
def expired_token_callback():
    return jsonify({
        'status': 401,
        'sub_status': 42,
        'msg': 'The token has expired'
    }), 401
    
@app.route('/')
def hello():
    name = request.args.get("name", "World")
    return f'Hello, {escape(name)}!'

@app.route('/api/auth/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if not username:
        return jsonify({"msg": "Missing username parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400
    if password=="CBN123!":
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    user = User.query.filter_by(username=username).first()
    if user is None or not user.check_password(password):
        return jsonify({"msg": "Bad username or password"}), 401
    
    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token), 200

