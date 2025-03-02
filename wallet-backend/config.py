from datetime import timedelta

class Config:
    SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://root:{'krishna1'.replace('@', '%40').replace(':', '%3A')}@localhost:3306/praavi_wallet"
    JWT_SECRET_KEY = 'supersecretkey'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)