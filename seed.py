from app import create_app
from models import create_default_users


app = create_app()


with app.app_context():
    create_default_users()


print("Database initialization completed.")
print()
print("Analyst account:")
print("Username: analyst")
print("Password: Analyst@123")
