import psycopg2
import os
from contextlib import contextmanager

@contextmanager
def get_db_connection():
    conn = psycopg2.connect(
        dbname=os.getenv('DB_NAME', 'deepguard_quest'),
        user=os.getenv('DB_USER', 'postgres'),
        password=os.getenv('DB_PASSWORD', 'root'),
        host=os.getenv('DB_HOST', 'localhost')
    )
    try:
        yield conn
    finally:
        conn.close()
