import yaml
import pika
import json
import uuid
from typing import Dict, Any
from datetime import datetime
import logging
import sys

from messageprocessing.messageencryption import MessageEncryption
from messageprocessing.messageverification import MessageVerification
from messageprocessing.messagedatefunctions import MessageDateFunctions

from sqlalchemy import create_engine, Column, String, Date, Enum, ForeignKey, JSON, Integer, Boolean, Text, TIMESTAMP, UniqueConstraint
from sqlalchemy.orm import sessionmaker, declarative_base, relationship

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(String(36), primary_key=True)
    username = Column(String(255), nullable=False, unique=True)
    email = Column(String(255), nullable=False)
    user_type = Column(Enum('human', 'machine'), nullable=False)
    expiry_date = Column(TIMESTAMP(timezone=True))
    details = relationship("UserDetail", back_populates="user")

class UserDetail(Base):
    __tablename__ = 'user_details'
    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey('users.id', ondelete='CASCADE'), index=True)
    details = Column(JSON)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    updated_at = Column(TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)
    user = relationship("User", back_populates="details")

class WebAuthnCredential(Base):
    __tablename__ = 'webauthn_credentials'
    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    credential_id = Column(Text, nullable=False, unique=True)
    public_key = Column(Text, nullable=False)
    sign_count = Column(Integer, default=0)
    transports = Column(String(255))
    attestation_format = Column(String(50))
    credential_type = Column(String(50), nullable=False)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    last_used_at = Column(TIMESTAMP, nullable=True)
    counter_last_updated = Column(TIMESTAMP, nullable=True)
    user = relationship("User", back_populates="webauthn_credentials")

User.webauthn_credentials = relationship("WebAuthnCredential", back_populates="user")

class OAuth2Signin(Base):
    __tablename__ = 'oauth2_signins'
    __table_args__ = (UniqueConstraint('user_id', 'name', name='uq_oauth2_signins_user_id_name'),)
    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    name = Column(String(50), nullable=False)
    provider = Column(String(50), nullable=False)
    openid_identifier = Column(String(255), nullable=False)
    access_token = Column(String(500))
    refresh_token = Column(String(500))
    token_expires_at = Column(TIMESTAMP)
    scopes = Column(String(255))
    id_token = Column(Text)
    last_refreshed = Column(TIMESTAMP)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    user = relationship("User", back_populates="oauth2_signins")

User.oauth2_signins = relationship("OAuth2Signin", back_populates="user")

class PublicSshKey(Base):
    __tablename__ = 'public_ssh_keys'
    __table_args__ = (UniqueConstraint('user_id', 'name', name='uq_public_ssh_keys_user_id_name'),)
    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    name = Column(String(50), nullable=False)
    ssh_key = Column(Text, nullable=False)
    key_type = Column(String(20), nullable=False)
    fingerprint = Column(String(255), unique=True)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    last_used_at = Column(TIMESTAMP, nullable=True)
    expiry_date = Column(TIMESTAMP(timezone=True))
    user = relationship("User", back_populates="public_ssh_keys")

User.public_ssh_keys = relationship("PublicSshKey", back_populates="user")

class LoginToken(Base):
    __tablename__ = 'login_tokens'
    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    token = Column(String(64), nullable=False, unique=True, index=True)
    revoked = Column(Boolean, default=False)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    expires_at = Column(TIMESTAMP)
    user = relationship("User", back_populates="login_tokens")

User.login_tokens = relationship("LoginToken", back_populates="user")

class Password(Base):
    __tablename__ = 'passwords'
    __table_args__ = (UniqueConstraint('user_id', name='uq_passwords_user_id'),)
    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    password_hash = Column(String(255), nullable=False)
    expiry_date = Column(TIMESTAMP)  # Changed from Date to TIMESTAMP
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    updated_at = Column(TIMESTAMP, default=datetime.utcnow)
    user = relationship("User", back_populates="passwords")

User.passwords = relationship("Password", back_populates="user")

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')




class UserRepository:
    """Handles user data operations including creation, updating, deletion, and retrieval."""

    def __init__(
            self, 
            settings: Dict[str, Any], 
            messageencryption: MessageEncryption, 
            messageverification: MessageVerification,
            messagedatefunctions: MessageDateFunctions):
        """
        Initialize the UserRepository with configuration settings.

        Args:
            settings (dict): Configuration settings loaded as a dictionary.
        """

        if not messageencryption:
            raise ValueError("Error: 'messageencryption' object is missing")
        else:
            self.messageencryption = messageencryption

        if not messageverification:
            raise ValueError("Error: 'messageverification' object is missing")
        else:
            self.messageverification = messageverification

        if not messagedatefunctions:
            raise ValueError("Error: 'messagedatefunctions' object is missing")
        else:
            self.messagedatefunctions = messagedatefunctions

        self.db_config = settings.get('database')
        if not self.db_config:
            raise ValueError("Error: 'database' section is missing in settings.yml")
        
        self.engine = create_engine(self.db_config.get('connection_string'), echo=False)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
        Base.metadata.create_all(self.engine)

        # Add a mapping from table names to model classes
        self.table_to_model = {
            'users': User,
            'user_details': UserDetail,
            'webauthn_credentials': WebAuthnCredential,
            'oauth2_signins': OAuth2Signin,
            'public_ssh_keys': PublicSshKey,
            'login_tokens': LoginToken,
            'passwords': Password
        }

        # Load the symmetric encryption key
        with open(settings['cryptography']['encryption_key_path'], 'rb') as key_file:
            self.encryption_key = key_file.read()

    def verify_signature(self, signaturestring, message: Dict[str, Any]) -> bool:
        """
        Verify the cryptographic signature of a message using all available public keys.

        Args:
            message (Dict[str, Any]): The message containing the signature.

        Returns:
            bool: True if the signature is valid with any public key, False otherwise.
        """
        return self.messageverification.verify_signature(signaturestring, message)

    def sign_message(self, message: Dict[str, Any]) -> str:
        """
        Sign a message using the private key.

        Args:
            message (Dict[str, Any]): The message to be signed.

        Returns:
            str: The hexadecimal representation of the signature.
        """
        return self.messageverification.sign_message(message)

    def parse_timestamp(self, timestamp_str: str) -> datetime:
        """
        Parse an ISO 8601 timestamp string into a timezone-aware datetime object.

        Args:
            timestamp_str (str): The timestamp string to parse.

        Returns:
            datetime: A timezone-aware datetime object.
        """
        return self.messagedatefunctions.parse_timestamp(timestamp_str)
        
    def encrypt_data(self, plaintext: str) -> str:
        """
        Encrypts the plaintext using AES CBC mode.

        Args:
            plaintext (str): The data to encrypt.

        Returns:
            str: The base64-encoded ciphertext.
        """
        return self.messageencryption.encrypt_data(plaintext)

    def decrypt_data(self, ciphertext_b64: str) -> str:
        """
        Decrypts the base64-encoded ciphertext using AES CBC mode.

        Args:
            ciphertext_b64 (str): The base64-encoded ciphertext.

        Returns:
            str: The decrypted plaintext.
        """
        return self.messageencryption.decrypt_data(ciphertext_b64)

    def handle_message(self, message_str: str) -> str:
        """
        Handle incoming messages with timezone-aware timestamps.

        Args:
            message_str (str): The incoming message as a JSON string.

        Returns:
            str: The response as a JSON string.
        """
        try:
            logging.info("\n ************************** Handling message **************************\n")
            logging.info(f"Received message: {message_str}")
            parsed_message = json.loads(message_str)
        except json.JSONDecodeError:
            return self._generate_response({}, "unknown", "error", "Invalid JSON format", error_code="INVALID_JSON")
        
        try:
            if not self.verify_signature(parsed_message.get('signature'), parsed_message):
                return self._generate_response(
                    parsed_message, 
                    parsed_message.get("operation", "unknown"), 
                    "error", 
                    "Invalid signature", 
                    error_code="INVALID_SIGNATURE"
                )
        except:
            return self._generate_response(
                parsed_message, 
                parsed_message.get("operation", "unknown"), 
                "error", 
                "Signature verification failed", 
                error_code="SIGNATURE_VERIFICATION_FAILED"
            )
        
        if parsed_message.get('encrypt'):
            print(f"Encrypted Message Received: {parsed_message}")
            encrypted_data = parsed_message.get('data')
            try:
                decrypted_data = self.decrypt_data(encrypted_data)
                parsed_message['data'] = json.loads(decrypted_data)
                print(f"Decrypted message: {parsed_message}")
            except Exception as e:
                logging.error(f"Decryption failed: {e}")
                return self._generate_response(parsed_message, "unknown", "error", "Decryption failed", error_code="DECRYPTION_FAILED")
        try:
            self.parse_timestamp(parsed_message.get("timestamp"))
        except ValueError:
            return json.dumps({"status": "error", "message": "Invalid timestamp format"})

        try:
            operation = parsed_message.get('operation')
            logging.info(f"\n########################## Handling message: {operation} ########################\n")
            data = parsed_message.get('data', {})

            if operation == 'batch_operations':
                response = self.handle_batch_operation(data, parsed_message)
            elif operation.startswith('create_'):
                response = self.create_record(operation, data, parsed_message)
            elif operation.startswith('update_'):
                response = self.update_record(operation, data, parsed_message)
            elif operation.startswith('delete_'):
                response = self.delete_record(operation, data, parsed_message)
            elif operation.startswith('get_'):
                response = self.get_record(operation, data, parsed_message)
            else:
                response = self._generate_response(
                    parsed_message, 
                    operation, 
                    "error", 
                    "Unknown operation", 
                    error_code="UNKNOWN_OPERATION"
                )
            logging.info(f"Message handled successfully: {parsed_message.get('operation')}")
        except json.JSONDecodeError:
             logging.error(f"JSON Decode Error: {parsed_message}")
             response = self._generate_response(
                 {}, 
                 "unknown", 
                 "error", 
                 "Invalid JSON format", 
                 error_code="INVALID_JSON"
             )
        except Exception as e:
            logging.error(f"Error handling message: {e}")
            response = self._generate_response(
                {}, 
                "unknown", 
                "error", 
                str(e), 
                error_code="GENERAL_ERROR"
            )
        
        if parsed_message.get('encrypt'):
            response_data = json.loads(response).get('data')
            encrypted_response_data = self.encrypt_data(json.dumps(response_data))
            response = json.loads(response)
            response['data'] = encrypted_response_data
            response = json.dumps(response)

        logging.info(f"\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Response: {response}!!!!!!!!!!!!!!!!!!!!!!!!!!\n")
        return response

    def _generate_response(self, original_message: Dict[str, Any], operation: str, status: str, message: str, data: Dict[str, Any] = None, error_code: str = None) -> str:
        """
        Generate a response message (common logic).
        """
        response = {
            "client_id": original_message.get("client_id"),
            "request_id": original_message.get("request_id"),
            "original_timestamp": original_message.get("timestamp"),
            "response_timestamp": datetime.utcnow().isoformat() + "Z",
            "operation": operation,
            "status": status,
            "message": message,
        }

        if data:
            response["data"] = data
        if error_code:
            response["error_code"] = error_code

        response['signature'] = self.sign_message(response)
        logging.debug(f"Response generated: {response}")
        return json.dumps(response, default=str)  # Added default=str to handle date serialization

    def handle_batch_operation(self, data: Dict[str, Any], original_message: Dict[str, Any]) -> str:
        """
        Handle batch operations for create, update, and delete actions.

        Args:
          data (Dict[str, Any]): The batch operation data.
          original_message (Dict[str, Any]): The original message.

        Returns:
          str: The JSON-encoded response.
        """
        results = []
        try:
            logging.debug("Starting batch operation")
            self.session.begin()
            for action in data.get("actions", []):
                action_type = action.get("action")
                action_data = action.get("data", {})
                
                if action_type.startswith('create_'):
                    result = self.create_record(action_type, action_data, original_message, batch=True)
                elif action_type.startswith('update_'):
                    result = self.update_record(action_type, action_data, original_message, batch=True)
                elif action_type.startswith('delete_'):
                    result = self.delete_record(action_type, action_data, original_message, batch=True)
                else:
                    result = self._generate_response(original_message, action_type, "error", f"Unknown batch action: {action_type}", error_code="UNKNOWN_BATCH_ACTION")
                results.append(json.loads(result))
                if json.loads(result).get('status') == 'error':
                    self.session.rollback()
                    logging.warning(f"Batch operation rolled back due to error in: {action_type}")
                    return self._generate_response(original_message, "batch_operation", "error", "Batch operation failed", error_code="BATCH_OPERATION_FAILED")

            self.session.commit()
            logging.info("Batch operation completed successfully")
            response_data = {"results": results}
            response = self._generate_response(original_message, "batch_operation", "success", "Batch operation completed successfully", data=response_data)
        
        except Exception as e:
            self.session.rollback()
            logging.error(f"Batch operation failed: {e}")
            response = self._generate_response(original_message, "batch_operation", "error", str(e), error_code="BATCH_OPERATION_FAILED")
        
        return response

    def convert_datetime(self, datetime_str: str) -> str:
        """
        Convert ISO 8601 datetime string to MySQL-compatible format.

        Args:
            datetime_str (str): The datetime string in ISO 8601 format.

        Returns:
            str: The datetime string in 'YYYY-MM-DD HH:MM:SS' format.
        """
        try:
            dt = datetime.fromisoformat(datetime_str.replace("Z", "+00:00"))  # Fixed reference
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            logging.error(f"Invalid datetime format: {datetime_str}")
            raise

    def get_model_class(self, operation: str):
        """
        Get the SQLAlchemy model class based on the operation.

        Args:
            operation (str): The operation identifier.

        Returns:
            SQLAlchemy model class.
        """
        
        table_name = self.get_table_name(operation)
        
        model = self.table_to_model.get(table_name)
        if not model:
            logging.error(f"No model found for table: {table_name}")
            raise ValueError(f"No model found for table: {table_name}")
        return model

    def create_record(self, operation: str, data: Dict[str, Any], original_message: Dict[str, Any], batch: bool = False) -> str:
        """
        Create a new record in the specified table.

        Args:
            operation (str): The create operation identifier.
            data (Dict[str, Any]): The data for the new record.
            original_message (Dict[str, Any]): The original incoming message.
            batch (bool): indicates if the call is in the scope of a batch operation.

        Returns:
            str: The JSON-encoded response.
        """
        # Remove the primary_key_map as all tables use 'id' as primary key
        primary_key_field = 'id'

        # Serialize dict fields to JSON strings and convert datetime fields
        for key, value in data.items():
            if key == 'expiry_date' and isinstance(value, str):
                data[key] = self.parse_timestamp(value)
            if isinstance(value, dict):
                data[key] = json.dumps(value)
            elif key in ['created_at', 'updated_at', 'last_used_at', 'counter_last_updated', 'token_expires_at', 'last_refreshed', 'expires_at']:
                data[key] = self.convert_datetime(value)

        # Generate a new UUID for the record or use the provided one
        new_id = data.get(primary_key_field, str(uuid.uuid4()))
        data[primary_key_field] = new_id

        model = self.get_model_class(operation)
        try:
            logging.debug(f"Creating record in table: {model.__tablename__}")
            new_record = model(**data)
            self.session.add(new_record)
            if not batch:
                self.session.commit()
            response_data = {primary_key_field: new_record.id}
            response = self._generate_response(
                original_message,
                operation,
                "success",
                f"{operation.replace('_', ' ').capitalize()} successfully",
                data=response_data
            )
            logging.info(f"Record created successfully in table: {model.__tablename__}")
        except Exception as e:
            logging.error(f"Error during create operation on table {model.__tablename__}: {e}")
            self.session.rollback()
            response = self._generate_response(
                original_message,
                operation,
                "error",
                str(e),
                error_code="CREATE_FAILED"
            )
        return response

    def update_record(self, operation: str, data: Dict[str, Any], original_message: Dict[str, Any], batch: bool = False) -> str:
        """
        Update an existing record in the specified table.

        Args:
            operation (str): The update operation identifier.
            data (Dict[str, Any]): The data for the update, including the record ID.
            original_message (Dict[str, Any]): The original incoming message.
            batch (bool): indicates if the call is in the scope of a batch operation.

        Returns:
            str: The JSON-encoded response.
        """
        model = self.get_model_class(operation)
        id = data.pop('id', None)
        if not id:
            logging.warning("Missing ID for update operation")
            return self._generate_response(original_message, operation, "error", "Missing ID for update", error_code="MISSING_ID")
        
        # Serialize dict fields to JSON strings and convert datetime fields
        for key, value in data.items():
            if key == 'expiry_date' and isinstance(value, str):
                data[key] = self.parse_timestamp(value)
            if isinstance(value, dict):
                data[key] = json.dumps(value)
            elif key in ['created_at', 'updated_at', 'last_used_at', 'counter_last_updated', 'token_expires_at', 'last_refreshed', 'expires_at']:
                data[key] = self.convert_datetime(value)
        
        try:
            logging.debug(f"Updating record in table: {model.__tablename__} with id: {id}")
            record = self.session.query(model).filter_by(id=id).first()
            if not record:
                logging.warning(f"Record not found in table {model.__tablename__} with id: {id}")
                return self._generate_response(original_message, operation, "error", "Record not found", error_code="NOT_FOUND")
            for key, value in data.items():
                setattr(record, key, value)
            if not batch:
                self.session.commit()
            response = self._generate_response(original_message, operation, "success", f"{operation.replace('_', ' ').capitalize()} successfully", data={"id": id})
            logging.info(f"Record updated successfully in table: {model.__tablename__}")
        except Exception as e:
            logging.error(f"Error during update operation on table {model.__tablename__}: {e}")
            self.session.rollback()
            response = self._generate_response(
                original_message,
                operation,
                "error",
                str(e),
                error_code="UPDATE_FAILED"
            )
        return response

    def delete_record(self, operation: str, data: Dict[str, Any], original_message: Dict[str, Any], batch: bool = False) -> str:
        """
        Delete a record from the specified table.

        Args:
            operation (str): The delete operation identifier.
            data (Dict[str, Any]): The data identifying the record to delete.
            original_message (Dict[str, Any]): The original incoming message.
            batch (bool): indicates if the call is in the scope of a batch operation.

        Returns:
            str: The JSON-encoded response.
        """
        model = self.get_model_class(operation)
        id = data.get('id') or data.get('user_id')
        if not id:
            logging.warning("Missing ID for delete operation")
            return self._generate_response(original_message, operation, "error", "Missing ID for delete", error_code="MISSING_ID")
        try:
            logging.debug(f"Deleting record from table: {model.__tablename__} with id: {id}")
            record = self.session.query(model).filter_by(id=id).first()
            if not record:
                logging.warning(f"Record not found in table {model.__tablename__} with id: {id}")
                return self._generate_response(original_message, operation, "error", "Record not found", error_code="NOT_FOUND")
            self.session.delete(record)
            if not batch:
                self.session.commit()
            response = self._generate_response(original_message, operation, "success", f"{operation.replace('_', ' ').capitalize()} successfully", data={"id": id})
            logging.info(f"Record deleted successfully from table: {model.__tablename__}")
        except Exception as e:
            logging.error(f"Error during delete operation on table {model.__tablename__}: {e}")
            self.session.rollback()
            response = self._generate_response(
                original_message,
                operation,
                "error",
                str(e),
                error_code="DELETE_FAILED"
            )
        return response

    def get_record_by_id(self, operation: str, data: Dict[str, Any], original_message: Dict[str, Any], batch: bool = False) -> str:
        """
        Retrieve a record from the specified table by ID.

        Args:
            operation (str): The get operation identifier.
            data (Dict[str, Any]): The data identifying the record to retrieve.
            original_message (Dict[str, Any]): The original incoming message.
            batch (bool): indicates if the call is in the scope of a batch operation.

        Returns:
            str: The JSON-encoded response.
        """
        model = self.get_model_class(operation)
        id = data.get('id') or data.get('user_id')
        if not id:
            logging.warning("Missing ID for get operation")
            return self._generate_response(original_message, operation, "error", "Missing ID for get", error_code="MISSING_ID")
        try:
            logging.debug(f"Retrieving record from table: {model.__tablename__} with id: {id}")
            record = self.session.query(model).filter_by(id=id).first()
            if not record:
                logging.warning(f"Record not found in table {model.__tablename__} with id: {id}")
                return self._generate_response(original_message, operation, "error", "Record not found", error_code="NOT_FOUND")
            # Convert record to dictionary excluding SQLAlchemy internal attributes
            record_dict = {column.key: getattr(record, column.key) for column in model.__table__.columns}
            response = self._generate_response(
                original_message,
                operation,
                "success",
                f"{operation.replace('_', ' ').capitalize()} successfully",
                data=record_dict
            )
            logging.info(f"Record retrieved successfully from table: {model.__tablename__}")
        except Exception as e:
            logging.error(f"Error during get operation on table {model.__tablename__}: {e}")
            response = self._generate_response(
                original_message,
                operation,
                "error",
                str(e),
                error_code="GET_FAILED"
            )
        return response

    def get_record_by_user_id(self, operation: str, data: Dict[str, Any], original_message: Dict[str, Any], batch: bool = False) -> str:
        """
        Retrieve a record from the specified table by ID.

        Args:
            operation (str): The get operation identifier.
            data (Dict[str, Any]): The data identifying the record to retrieve.
            original_message (Dict[str, Any]): The original incoming message.
            batch (bool): indicates if the call is in the scope of a batch operation.

        Returns:
            str: The JSON-encoded response.
        """
        model = self.get_model_class(operation)
        searchparam = data.get('user_id')
        if not searchparam:
            logging.warning("Missing user_id for get operation")
            return self._generate_response(original_message, operation, "error", "Missing user_id for get", error_code="MISSING_USER_ID")
        try:
            logging.debug(f"Retrieving record from table: {model.__tablename__} with user_id: {searchparam}")
            records = self.session.query(model).filter_by(user_id=searchparam).all()
            if not records:
                logging.warning(f"Records not found in table {model.__tablename__} with user_id: {searchparam}")
                return self._generate_response(original_message, operation, "error", "Records not found", error_code="NOT_FOUND")

            response_data = []
            for record in records:
                record_dict = {column.key: getattr(record, column.key) for column in model.__table__.columns}
                response_data.append(record_dict)

            response = self._generate_response(
                original_message,
                operation,
                "success",
                f"{operation.replace('_', ' ').capitalize()} successfully",
                data=response_data

            )
            logging.info(f"Records retrieved successfully from table: {model.__tablename__}")
        except Exception as e:
            logging.error(f"Error during get operation on table {model.__tablename__}: {e}")
            response = self._generate_response(
                original_message,
                operation,
                "error",
                str(e),
                error_code="GET_FAILED"
            )
        return response

    def get_users_by_username(self, operation: str, data: Dict[str, Any], original_message: Dict[str, Any], batch: bool = False) -> str:
        """
        Retrieve a user record from the users table by username.

        Args:
            operation (str): The get operation identifier.
            data (Dict[str, Any]): The data identifying the record to retrieve.
            original_message (Dict[str, Any]): The original incoming message.
            batch (bool): indicates if the call is in the scope of a batch operation.

        Returns:
            str: The JSON-encoded response.
        """
        model = User
        searchparam = data.get('username')
        if not searchparam:
            logging.warning("Missing username for get operation")
            return self._generate_response(original_message, operation, "error", "Missing username for get", error_code="MISSING_USERNAME")
        try:
            logging.debug(f"Retrieving record from table: {model.__tablename__} with username: {searchparam}")
            record = self.session.query(model).filter_by(username=searchparam).first()
            if not record:
                logging.warning(f"Record not found in table {model.__tablename__} with username: {searchparam}")
                return self._generate_response(original_message, operation, "error", "Record not found", error_code="NOT_FOUND")
            # Convert record to dictionary excluding SQLAlchemy internal attributes
            record_dict = {column.key: getattr(record, column.key) for column in model.__table__.columns}
            response = self._generate_response(
                original_message,
                operation,
                "success",
                f"{operation.replace('_', ' ').capitalize()} successfully",
                data=record_dict
            )
            logging.info(f"Record retrieved successfully from table: {model.__tablename__}")
        except Exception as e:
            logging.error(f"Error during get operation on table {model.__tablename__}: {e}")
            response = self._generate_response(
                original_message,
                operation,
                "error",
                str(e),
                error_code="GET_FAILED"
            )
        return response
        
    def get_record(self, operation: str, data: Dict[str, Any], original_message: Dict[str, Any], batch: bool = False) -> str:
        """
        Retrieve a record from the specified table.

        Args:
            operation (str): The get operation identifier.
            data (Dict[str, Any]): The data identifying the record to retrieve.
            original_message (Dict[str, Any]): The original incoming message.
            batch (bool): indicates if the call is in the scope of a batch operation.

        Returns:
            str: The JSON-encoded response.
        """
        if operation == 'get_users_by_username':
            return self.get_users_by_username(operation, data, original_message, batch)
        elif operation.endswith('by_user_id'):
            return self.get_record_by_user_id(operation, data, original_message, batch)
        else:
            return self.get_record_by_id(operation, data, original_message, batch)


    def get_table_name(self, operation: str) -> str:
        """
        Map operation names to table names.

        Args:
            operation (str): The operation identifier.

        Returns:
            str: The corresponding table name.
        """
        operation_to_table = {
            'create_users': 'users',
            'update_users': 'users',
            'delete_users': 'users',
            'get_users': 'users',
            'get_users_by_username': 'users',
            'create_user_details': 'user_details',
            'update_user_details': 'user_details',
            'delete_user_details': 'user_details',
            'get_user_details': 'user_details',
            'get_user_details_by_user_id': 'user_details',
            'create_passwords': 'passwords',
            'update_passwords': 'passwords',
            'delete_passwords': 'passwords',
            'get_passwords': 'passwords',
            'get_passwords_by_user_id': 'passwords',
            'create_webauthn_credentials': 'webauthn_credentials',
            'update_webauthn_credentials': 'webauthn_credentials',
            'delete_webauthn_credentials': 'webauthn_credentials',
            'get_webauthn_credentials': 'webauthn_credentials',
            'get_webauthn_credentials_by_user_id': 'webauthn_credentials',
            'create_oauth2_signins': 'oauth2_signins',
            'update_oauth2_signins': 'oauth2_signins',
            'delete_oauth2_signins': 'oauth2_signins',
            'get_oauth2_signins': 'oauth2_signins',
            'get_oauth2_signins_by_user_id': 'oauth2_signins',
            'create_public_ssh_keys': 'public_ssh_keys',
            'update_public_ssh_keys': 'public_ssh_keys',
            'delete_public_ssh_keys': 'public_ssh_keys',
            'get_public_ssh_keys': 'public_ssh_keys',
            'get_public_ssh_keys_by_user_id': 'public_ssh_keys',
            'create_login_tokens': 'login_tokens',
            'update_login_tokens': 'login_tokens',
            'delete_login_tokens': 'login_tokens',
            'get_login_tokens': 'login_tokens',
            'get_login_tokens_by_user_id': 'login_tokens',
            # Add more mappings as needed

        }
        table = operation_to_table.get(operation)
        if not table:
            logging.error(f"No table mapping found for operation: {operation}")
            raise ValueError(f"No table mapping found for operation: {operation}")
        return table

def load_settings(file_path):
    with open(file_path, 'r') as file:
        settings = yaml.safe_load(file)
    return settings

def on_request(ch, method, properties, body):
    user_repository = UserRepository(
        settings=settings, 
        messageverification = MessageVerification(settings=settings),
        messageencryption = MessageEncryption(settings=settings),
        messagedatefunctions = MessageDateFunctions())  # Initialize UserRepository with settings

    # Process the message
    logging.debug(f"Received message: {body}")

    # Handle the message
    response = user_repository.handle_message(body)

    # Send response
    ch.basic_publish(
        exchange='',
        routing_key='user_repository_responses',
        properties=pika.BasicProperties(correlation_id=properties.correlation_id),
        body=response
    )

    # Acknowledge the message
    ch.basic_ack(delivery_tag=method.delivery_tag)

def main():
    # Load settings once
    global settings
    settings = load_settings('settings.yml')
    
    # RabbitMQ connection parameters
    rabbitmq = settings.get('rabbitmq')
    if not rabbitmq:
        print("Error: 'rabbitmq' section is missing in settings.yml")
        sys.exit(1)
    
    rabbitmq_host = rabbitmq.get('host')
    rabbitmq_user = rabbitmq.get('user')
    rabbitmq_password = rabbitmq.get('password')
    
    if not rabbitmq_host or not rabbitmq_user or not rabbitmq_password:
        print("Error: One or more RabbitMQ configuration parameters are missing in settings.yml")
        sys.exit(1)
    
    # Establish connection to RabbitMQ
    credentials = pika.PlainCredentials(rabbitmq_user, rabbitmq_password)
    connection = pika.BlockingConnection(pika.ConnectionParameters(host=rabbitmq_host, credentials=credentials))
    channel = connection.channel()
    
    # Declare queues
    channel.queue_declare(queue='user_repository')
    channel.queue_declare(queue='user_repository_responses')
    
    # Set up consumer
    channel.basic_qos(prefetch_count=1)
    channel.basic_consume(queue='user_repository', on_message_callback=on_request)
    
    print("Waiting for messages. To exit press CTRL+C")
    channel.start_consuming()

if __name__ == "__main__":
    main()