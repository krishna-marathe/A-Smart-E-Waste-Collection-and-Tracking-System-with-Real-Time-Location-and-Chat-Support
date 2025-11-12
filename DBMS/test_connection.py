import psycopg2
from sqlalchemy import create_engine

# Test different connection strings
connection_strings = [
    'postgresql://postgres:Jignesh#087@localhost:5432/ewaste_db',
    'postgresql://postgres:Jignesh%23087@localhost:5432/ewaste_db',
    'postgresql://postgres:Jignesh#087@127.0.0.1:5432/ewaste_db',
    'postgresql://postgres:Jignesh%23087@127.0.0.1:5432/ewaste_db',
]

print("Testing psycopg2 direct connections:")
for conn_str in connection_strings:
    try:
        conn = psycopg2.connect(conn_str)
        print(f"✅ SUCCESS: {conn_str}")
        conn.close()
        break
    except Exception as e:
        print(f"❌ FAILED: {conn_str}")
        print(f"   Error: {str(e)[:100]}")

print("\nTesting SQLAlchemy connections:")
for conn_str in connection_strings:
    try:
        engine = create_engine(conn_str)
        with engine.connect() as conn:
            print(f"✅ SUCCESS: {conn_str}")
            break
    except Exception as e:
        print(f"❌ FAILED: {conn_str}")
        print(f"   Error: {str(e)[:100]}")
