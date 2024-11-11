from flask import current_app
from mysql.connector import Error, connect
import mysql.connector
import logging
from contextlib import contextmanager
import json
from datetime import datetime
import hmac
import hashlib
import os
import base64
from cryptography.fernet import Fernet

# Configure logging
logging.basicConfig(
    filename='database.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)

class SecurityConfig:
    # Generate or load keys (in production, these should be loaded from secure environment variables)
    ENCRYPTION_KEY = Fernet.generate_key()
    INTEGRITY_KEY = os.urandom(32)
    HMAC_KEY = os.urandom(32)

class DataConfidentiality:
    def __init__(self, key=SecurityConfig.ENCRYPTION_KEY):
        self.fernet = Fernet(key)

    def encrypt_sensitive_fields(self, data):
        """Encrypt sensitive fields (gender and age)"""
        encrypted_data = data.copy()
        for field in ['gender', 'age']:
            if field in data:
                value = str(data[field]).encode()
                encrypted_value = self.fernet.encrypt(value)
                encrypted_data[field] = base64.b64encode(encrypted_value).decode()
        return encrypted_data

    def decrypt_sensitive_fields(self, data):
        """Decrypt sensitive fields if user has permission"""
        decrypted_data = data.copy()
        for field in ['gender', 'age']:
            if field in data and data[field]:
                try:
                    encrypted_value = base64.b64decode(data[field])
                    decrypted_value = self.fernet.decrypt(encrypted_value)
                    decrypted_data[field] = decrypted_value.decode()
                except Exception as e:
                    logging.error(f"Decryption error for field {field}: {str(e)}")
                    decrypted_data[field] = None
        return decrypted_data

class IntegrityProtection:
    def __init__(self, key=SecurityConfig.INTEGRITY_KEY):
        self.key = key

    def sign_record(self, record):
        """Sign individual record for integrity"""
        record_str = json.dumps(record, sort_keys=True)
        signature = hmac.new(
            self.key,
            record_str.encode(),
            hashlib.sha256
        ).hexdigest()
        return signature

    def verify_record(self, record, signature):
        """Verify individual record integrity"""
        record_str = json.dumps(record, sort_keys=True)
        expected_signature = hmac.new(
            self.key,
            record_str.encode(),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(signature, expected_signature)

    def compute_merkle_root(self, records):
        """Compute Merkle root for query completeness"""
        if not records:
            return hashlib.sha256(b'empty').digest()

        hashes = [
            hashlib.sha256(json.dumps(r, sort_keys=True).encode()).digest()
            for r in records
        ]

        while len(hashes) > 1:
            if len(hashes) % 2 == 1:
                hashes.append(hashes[-1])
            hashes = [
                hashlib.sha256(h1 + h2).digest()
                for h1, h2 in zip(hashes[::2], hashes[1::2])
            ]
        return hashes[0].hex()

class AccessControl:
    @staticmethod
    def filter_data_by_group(data, group):
        """Filter data based on user group"""
        if group == 'H':
            return data
        # Group R cannot access first_name and last_name
        filtered_data = data.copy()
        filtered_data.pop('first_name', None)
        filtered_data.pop('last_name', None)
        return filtered_data

    @staticmethod
    def can_add_record(group):
        """Check if user can add records"""
        return group == 'H'

class DatabaseConfig:
    HOST = 'localhost'
    USER = 'root'
    PASSWORD = 'root'
    DATABASE = 'healthcare_db'

    TABLES = {}
    TABLES['users'] = (
        "CREATE TABLE IF NOT EXISTS `users` ("
        "  `id` int NOT NULL AUTO_INCREMENT,"
        "  `username` varchar(80) NOT NULL UNIQUE,"
        "  `password_hash` varchar(255) NOT NULL,"
        "  `salt` varchar(64) NOT NULL,"  # Added salt field
        "  `group` varchar(10) NOT NULL,"
        "  `last_login` datetime DEFAULT NULL,"
        "  `login_attempts` int DEFAULT 0,"
        "  `locked_until` datetime DEFAULT NULL,"
        "  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,"
        "  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,"
        "  PRIMARY KEY (`id`),"
        "  INDEX `idx_username` (`username`),"
        "  INDEX `idx_group` (`group`)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
    )

    TABLES['records'] = (
        "CREATE TABLE IF NOT EXISTS `records` ("
        "  `id` int NOT NULL AUTO_INCREMENT,"
        "  `user_id` int NOT NULL,"
        "  `first_name` varchar(255),"
        "  `last_name` varchar(255),"
        "  `encrypted_age` varchar(255),"
        "  `encrypted_gender` varchar(255),"
        "  `condition` varchar(255),"
        "  `medication` varchar(255),"
        "  `signature` varchar(64) NOT NULL,"
        "  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,"
        "  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,"
        "  PRIMARY KEY (`id`),"
        "  FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,"
        "  INDEX `idx_user_created` (`user_id`, `created_at`)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
    )

class SecureDB:
    def __init__(self):
        self.config = DatabaseConfig
        self.confidentiality = DataConfidentiality()
        self.integrity = IntegrityProtection()
        self.access_control = AccessControl()
    def _get_db_connection(self, database=None):
        """Create a database connection"""
        try:
            connection_config = {
                'host': self.config.HOST,
                'user': self.config.USER,
                'password': self.config.PASSWORD,
                'autocommit': False,
                'buffered': True
            }
            if database:
                connection_config['database'] = database

            return mysql.connector.connect(**connection_config)
        except Error as err:
            logging.error(f"Error connecting to MySQL: {err}")
            raise

    def create_database(self):
        """Create database and tables if they don't exist"""
        conn = None
        try:
            # First connect without database
            conn = self._get_db_connection()
            cursor = conn.cursor()

            # Create database if it doesn't exist
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {self.config.DATABASE} "
                           "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
            cursor.execute(f"USE {self.config.DATABASE}")

            # Create tables
            for table_name, table_sql in self.config.TABLES.items():
                try:
                    cursor.execute(table_sql)
                    logging.info(f"Created table {table_name}")
                except Error as err:
                    logging.error(f"Error creating table {table_name}: {err}")
                    raise

            conn.commit()
            logging.info("Database and tables created successfully")

        except Error as err:
            logging.error(f"Error creating database: {err}")
            if conn:
                conn.rollback()
            raise
        finally:
            if conn and conn.is_connected():
                cursor.close()
                conn.close()

    def get_user_data(self, username, group):
        """Get user data based on permissions"""
        conn = None
        try:
            conn = self._get_db_connection(self.config.DATABASE)
            cursor = conn.cursor(dictionary=True)

            if group == 'H':  # High privilege group
                query = """
                    SELECT r.*, u.username 
                    FROM records r 
                    JOIN users u ON r.user_id = u.id 
                    ORDER BY r.created_at DESC 
                    LIMIT 1000
                """
                cursor.execute(query)
            else:
                query = """
                    SELECT r.* 
                    FROM records r 
                    JOIN users u ON r.user_id = u.id 
                    WHERE u.username = %s 
                    ORDER BY r.created_at DESC
                """
                cursor.execute(query, (username,))

            result = cursor.fetchall()
            return result

        except Error as err:
            logging.error(f"Error fetching user data: {err}")
            raise
        finally:
            if conn and conn.is_connected():
                cursor.close()
                conn.close()

    def add_record(self, data, username):
        """Add new record with security measures"""
        conn = None
        try:
            conn = self._get_db_connection(self.config.DATABASE)
            cursor = conn.cursor(dictionary=True)

            # Get user_id and group
            cursor.execute(
                "SELECT id, `group` FROM users WHERE username = %s",
                (username,)
            )
            user_data = cursor.fetchone()

            if not user_data:
                raise ValueError("User not found")

            if not self.access_control.can_add_record(user_data['group']):
                raise ValueError("Insufficient permissions")

            # Encrypt sensitive data
            data_to_store = {
                'first_name': data.get('first_name'),
                'last_name': data.get('last_name'),
                'condition': data.get('condition'),
                'medication': data.get('medication')
            }

            # Encrypt sensitive fields
            encrypted_fields = self.confidentiality.encrypt_sensitive_fields({
                'age': data.get('age'),
                'gender': data.get('gender')
            })

            data_to_store['encrypted_age'] = encrypted_fields.get('age')
            data_to_store['encrypted_gender'] = encrypted_fields.get('gender')

            # Generate signature
            signature = self.integrity.sign_record(data_to_store)
            data_to_store['signature'] = signature
            data_to_store['user_id'] = user_data['id']

            # Insert record
            columns = ', '.join(data_to_store.keys())
            placeholders = ', '.join(['%s'] * len(data_to_store))
            insert_query = f"""
                INSERT INTO records ({columns})
                VALUES ({placeholders})
            """

            cursor.execute(insert_query, list(data_to_store.values()))
            conn.commit()

            return True

        except Exception as e:
            if conn:
                conn.rollback()
            logging.error(f"Error adding record: {str(e)}")
            raise
        finally:
            if conn and conn.is_connected():
                cursor.close()
                conn.close()

    def get_user_data(self, username, group):
        """Get user data with security measures"""
        conn = None
        try:
            conn = self._get_db_connection(self.config.DATABASE)
            cursor = conn.cursor(dictionary=True)

            # Get user_id
            cursor.execute(
                "SELECT id FROM users WHERE username = %s",
                (username,)
            )
            user_data = cursor.fetchone()

            if not user_data:
                raise ValueError("User not found")

            # Fetch records based on group permissions
            query = """
                SELECT * FROM records 
                WHERE user_id = %s OR %s = 'H'
                ORDER BY created_at DESC
            """
            cursor.execute(query, (user_data['id'], group))
            records = cursor.fetchall()

            verified_records = []
            for record in records:
                # Verify record integrity
                signature = record.pop('signature', None)
                record_copy = record.copy()

                if signature and self.integrity.verify_record(record_copy, signature):
                    # Decrypt sensitive fields for group H
                    if group == 'H':
                        if record['encrypted_age']:
                            record['age'] = self.confidentiality.decrypt_sensitive_fields(
                                {'age': record['encrypted_age']}
                            )['age']
                        if record['encrypted_gender']:
                            record['gender'] = self.confidentiality.decrypt_sensitive_fields(
                                {'gender': record['encrypted_gender']}
                            )['gender']

                    # Remove encrypted fields
                    record.pop('encrypted_age', None)
                    record.pop('encrypted_gender', None)

                    # Apply group-based filtering
                    filtered_record = self.access_control.filter_data_by_group(record, group)
                    verified_records.append(filtered_record)

            # Generate Merkle root for query completeness
            merkle_root = self.integrity.compute_merkle_root(verified_records)

            return {
                'records': verified_records,
                'merkle_root': merkle_root
            }

        except Exception as e:
            logging.error(f"Error fetching user data: {str(e)}")
            raise
        finally:
            if conn and conn.is_connected():
                cursor.close()
                conn.close()


def create_admin_user(db_instance):
    """Create admin user if it doesn't exist"""
    conn = None
    try:
        conn = db_instance._get_db_connection(db_instance.config.DATABASE)
        cursor = conn.cursor()

        # Check if admin exists
        cursor.execute("SELECT id FROM users WHERE username = 'admin'")
        if not cursor.fetchone():
            from werkzeug.security import generate_password_hash

            # Create admin user
            admin_password = "Admin@123456"  # Change this in production
            password_hash = generate_password_hash(admin_password, method='pbkdf2:sha256:260000')

            insert_query = """
                INSERT INTO users (username, password_hash, `group`) 
                VALUES (%s, %s, %s)
            """
            cursor.execute(insert_query, ('admin', password_hash, 'H'))
            conn.commit()
            logging.info("Admin user created successfully")
            print("Admin user created successfully")

    except Error as err:
        logging.error(f"Error creating admin user: {err}")
        if conn:
            conn.rollback()
        raise
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()


def setup_database():
    """Setup database and initial admin user"""
    try:
        db = SecureDB()
        print("Creating database and tables...")
        db.create_database()
        print("Database and tables created successfully")

        print("Creating admin user...")
        create_admin_user(db)
        print("Database setup completed successfully")

    except Exception as err:
        logging.error(f"Database setup failed: {err}")
        print(f"Error during database setup: {err}")
        raise


if __name__ == "__main__":
    setup_database()