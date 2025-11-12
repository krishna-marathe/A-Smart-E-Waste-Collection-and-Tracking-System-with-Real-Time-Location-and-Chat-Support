from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Jignesh#087@localhost:5432/ewaste_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

print(f"Connection string: {app.config['SQLALCHEMY_DATABASE_URI']}")

db = SQLAlchemy(app)

print("SQLAlchemy initialized successfully")

with app.app_context():
    try:
        db.create_all()
        print("✅ Database connection successful!")
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
