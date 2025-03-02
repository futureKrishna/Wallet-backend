from flask import Flask
from flask_cors import CORS
from config import Config
from extensions import db, bcrypt, jwt
from routes import wallet_routes

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    CORS(app,origins="http://127.0.0.1:5173")
    db.init_app(app)
    bcrypt.init_app(app)
    jwt.init_app(app)

    app.register_blueprint(wallet_routes)

    return app

if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        db.create_all()
    app.run(port=4000, debug=True)
