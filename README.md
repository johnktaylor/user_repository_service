# User Repository

## Overview

The User Repository is a backend service responsible for managing user data, including creation, updating, retrieval, and deletion of user records. It ensures data consistency and security through the use of cryptographic signatures and encryption.

## Features

- **CRUD Operations:** Create, read, update, and delete user data across multiple tables.
- **Batch Operations:** Perform multiple actions in a single, atomic transaction.
- **Secure Communication:** Utilizes cryptographic signatures to verify message integrity and authenticity.
- **Encryption:** Encrypts sensitive data using AES encryption.
- **Integration with RabbitMQ:** Listens for and processes messages from RabbitMQ message queues.

## Setup Instructions

### Prerequisites

- **Python 3.8+**
- **MySQL Database**
- **RabbitMQ Server**
- **OpenSSL:** Ensure OpenSSL is installed and accessible in your system's PATH for key generation and management.

### Installation

1. **Clone the Repository:**
    ```bash
    git clone https://github.com/yourusername/user_repository.git
    cd user_repository
    ```

2. **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3. **Configure Settings:**
    Create a `settings.yml` file based on the `template_for_settings.yml` file. Update the `settings.yml` file with your specific configurations. Ensure the `connection_string` is correctly set for SQLAlchemy:
    ```yaml
    database:
      connection_string: mysql+mysqlconnector://userrepodb:password@localhost/userrepo

    cryptography:
      private_key_paths:
        user_repository: path/to/private_key.pem
        integration_tests: path/to/integration_tests_private_key.pem
        unit_tests: path/to/unit_tests_private_key.pem
      public_key_paths:
        user_repository: path/to/public_key.pem
        integration_tests: path/to/integration_tests_public_key.pem
        unit_tests: path/to/unit_tests_public_key.pem
      public_keys_dir: path/to/public_keys_directory
      encryption_key_path: path/to/encryption_key.bin

    rabbitmq:
      host: localhost
      user: your_rabbitmq_user
      password: your_rabbitmq_password
    ```

4. **Generate Cryptographic Keys:**
    ```bash
    python generate_keys.py --regenerate-all-keys
    ```

5. **Initialize the Database:**
    Run the SQL script to set up the necessary database schema:
    ```bash
    mysql -u your_db_user -p < /path/to/init.sql
    ```

### Running the Service

Start the User Repository service:
```bash
python user_repository.py
```
The service will connect to RabbitMQ and begin listening for incoming messages on the `user_repository` queue.

## Usage

When interacting with the User Repository API, ensure all timestamp fields are in ISO 8601 format with timezone information.

### Example JSON Payload for Creating a User
```json
{
  "client_id": "client123",
  "request_id": "req456",
  "timestamp": "2023-01-01T12:00:00Z",
  "operation": "create_users",
  "encrypt": true,
  "data": {
    "username": "john_doe",
    "email": "john@example.com",
    "user_type": "human",
    "expiry_date": "2024-01-01T00:00:00Z"
  },
  "signature": "base64_encoded_signature"
}
```

## Extending the Service

### Adding New Models

1. **Define the Model:**
    Add a new SQLAlchemy model class in `user_repository.py`:
    ```python
    class NewModel(Base):
        __tablename__ = 'new_model'
        id = Column(String(36), primary_key=True)
        name = Column(String(50), nullable=False)
        # Add other fields as needed
    ```

2. **Update the Table-to-Model Mapping:**
    Add the new model to the `table_to_model` dictionary in the `UserRepository` class:
    ```python
    self.table_to_model = {
        # ...existing mappings...
        'new_model': NewModel
    }
    ```

3. **Create the Table:**
    Run the following command to create the new table in the database:
    ```bash
    python -c "from user_repository import Base, engine; Base.metadata.create_all(engine)"
    ```

### Adding New Operations

1. **Define the Operation:**
    Add a new method in the `UserRepository` class to handle the new operation:
    ```python
    def new_operation(self, data: Dict[str, Any], original_message: Dict[str, Any]) -> str:
        # Implement the operation logic
        response = self._generate_response(original_message, "new_operation", "success", "Operation completed successfully")
        return response
    ```

2. **Update the Operation Mapping:**
    Add the new operation to the `get_table_name` method in the `UserRepository` class:
    ```python
    operation_to_table = {
        # ...existing mappings...
        'new_operation': 'new_model'
    }
    ```

3. **Handle the Operation:**
    Update the `handle_message` method to call the new operation:
    ```python
    if operation == 'new_operation':
        response = self.new_operation(data, parsed_message)
    ```

## Testing

### Running Unit Tests
```bash
python -m unittest discover -s tests/unit_tests.py
```

### Running Integration Tests
```bash
python -m unittest discover -s tests/integration_tests.py
```

## Contributing

Contributions are welcome! Please ensure that all new features adhere to the existing code structure and conventions.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE.md) file for details.