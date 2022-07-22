import config

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from marshmallow import Schema, fields, validate

from werkzeug.security import generate_password_hash, check_password_hash
import jwt

from web3 import Web3
from web3.auto import w3
from eth_account.messages import encode_defunct

from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from apispec_webframeworks.flask import FlaskPlugin


app = Flask(__name__)

app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://{user}:{password}@localhost/{db}'.format(
    user=config.POSTGRES_USER,
    password=config.POSTGRES_PASSWORD,
    db=config.POSTGRES_DB
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)
spec = APISpec(
    title='flask-api-swagger-doc',
    version='1.0.0',
    openapi_version='3.0.3',
    plugins=[FlaskPlugin(), MarshmallowPlugin()]
)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    surname = db.Column(db.String, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    eth_address = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    auth_token = db.Column(db.String)


password_regex = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$"


class UserSchema(Schema):
    name = fields.Str()
    email = fields.Email()
    surname = fields.Str()
    eth_address = fields.Str()
    password = fields.Str(validate=validate.Regexp(password_regex))


class AuthSchema(Schema):
    email = fields.Email()
    password = fields.Str(validate=validate.Regexp(password_regex))


@app.route('/sign_up', methods=['POST'])
def sign_up():
    """
    User registration
    ---
    post:
      summary: Creates a user.
      requestBody:
        required: true
        content:
          application/json:
            schema: UserSchema
      responses:
        400:
          description: Bad request
        200:
          description: User registered
          content:
            application/json:
              schema:
                type: object
                properties:
                  signature:
                    type: string
                    format: eth_sign
    """
    json_data = request.get_json()
    if not json_data:
        return jsonify({'message': 'Bad request'}), 400
    try:
        data = UserSchema().load(json_data)
        password_hash = generate_password_hash(data['password'])
        user = User(
            name=data['name'],
            surname=data['surname'],
            email=data['email'],
            password=password_hash,
            eth_address=data['eth_address']
        )
        db.session.add(user)
        db.session.commit()

    except Exception as Err:
        db.session.rollback()
        return jsonify({"message": 'Bad request', 'error': str(Err)}), 400

    keccak256 = Web3.solidityKeccak(['uint256'], [user.id])
    eth_hash = encode_defunct(keccak256)
    signed_message = w3.eth.account.sign_message(eth_hash, private_key=config.PRIVATE_KEY)
    return jsonify({"message": Web3.toHex(signed_message.signature)}), 200


@app.route("/sign_in", methods=['POST'])
def sign_in():
    """
    User authentication
    ---
    post:
      summary: Authenticate user
      requestBody:
        required: true
        content:
          application/json:
            schema: AuthSchema
      responses:
        400:
          description: Bad request
        401:
          description: Bad email or password
        200:
          description: User Authenticated
          content:
            application/json:
              schema:
                type: object
                properties:
                  auth_token:
                    type: string
                    format: JWT
    """

    json_data = request.get_json()
    if not json_data:
        return jsonify({'message': 'No input data provided'}), 400
    try:
        data = AuthSchema().load(json_data)
        user = User.query.filter_by(email=data['email']).first()
        if not user:
            return jsonify({'message': 'User not found'}), 401

        if check_password_hash(user.password, data['password']):
            token = jwt.encode(
                {'user_id': user.id},
                app.config['SECRET_KEY'])
            user.auth_token = token.decode('UTF-8')
            db.session.commit()
            return jsonify({'auth_token': token.decode('utf-8')})

        return jsonify({'message': 'Wrong password'}), 401

    except Exception as Err:
        return jsonify({'message': 'Could not verify', 'error': str(Err)}), 401


@app.route("/user", methods=['GET'])
def user_info():
    """
    Return user information by auth_token
    ---
    get:
      summary: Return user information by auth_token
      parameters:
        - in: header
          name: Bearer
          schema:
            type: string
          required: true
      responses:
        400:
          description: Bad request
        200:
          description: User Authenticated
          content:
            application/json:
              schema:
                type: object
                properties:
                  name:
                    type: string
                  surname:
                    type: string
                  email:
                    type: string
                    format: email
                  eth_address:
                    type: string
                    format: eth wallet
    """
    token = None
    if 'Bearer' in request.headers:
        token = request.headers['Bearer']
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'])
        user = User.query.filter_by(id=data['user_id']).first()
        if token == user.auth_token:
            return jsonify({
                "name": user.name,
                "surname": user.surname,
                "email": user.email,
                "eth_address": user.eth_address
                }), 200
        return jsonify({'message': 'Token is invalid!'}), 400
    except Exception as Err:
        return jsonify({'message': 'Token is invalid!', 'error': str(Err)}), 400


@app.route('/api/spec.json')
def create_swagger_spec():
    return jsonify(spec.to_dict())


with app.test_request_context():
    spec.path(view=sign_up)
    spec.path(view=sign_in)
    spec.path(view=user_info)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
