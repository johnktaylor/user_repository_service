# User Repository Service

## Overview
The User Repository Service manages user data and supports secure operations through cryptographic signatures and encryption. It handles CRUD operations, batch processing, and integrates with messaging systems like RabbitMQ.

Please note this software is currently under heavy development.

## Features
- **CRUD Operations:** Create, read, update, and delete user data.
- **Batch Operations:** Execute grouped actions atomically.
- **Secure Communication:** Uses digital signatures and AES encryption.
- **Message Processing:** Supports JSON-based messaging with RabbitMQ integration.

## Setup
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
    - Create a `settings.yml` file (refer to `template_for_settings.yml`) with your database, cryptographic, and RabbitMQ configurations.
4. **Generate Cryptographic Keys:**
    ```bash
    python generate_keys.py --regenerate-all-keys
    ```
5. **Initialize the Database:**
    ```bash
    mysql -u your_db_user -p < init.sql
    ```

## Running the Service
- **Start the Service:**
    ```bash
    python user_repository.py
    ```
- The service listens for messages on the RabbitMQ queue `user_repository` and sends responses to the `user_repository_responses` queue.

## Usage
- **Message Format:**  
  The service expects JSON messages containing fields like `client_id`, `request_id`, `timestamp`, `operation`, and optionally `data`, `signature`, and an `encrypt` flag.
  
- **Example Message:**  
    ```json
    {
      "client_id": "client123",
      "request_id": "req-456",
      "timestamp": "2023-10-10T12:00:00Z",
      "operation": "create_users",
      "data": {
         "username": "jdoe",
         "email": "jdoe@example.com",
         "user_type": "human"
      },
      "signature": "abcdef123456..."
    }
    ```
  
- **Sending a Message:**  
  You can publish messages to the `user_repository` queue using any RabbitMQ client or command-line tool. For example, using `rabbitmqadmin`:
    ```bash
    rabbitmqadmin publish routing_key=user_repository payload='{"client_id":"client123", "request_id":"req-456", "timestamp":"2023-10-10T12:00:00Z", "operation":"create_users", "data":{"username":"jdoe", "email":"jdoe@example.com", "user_type":"human"}, "signature":"abcdef123456..."}'
    ```
  
- **Expected Response:**  
  The service processes the message and sends a response, including a status, message, and a new signature, to the `user_repository_responses` queue.

### Additional Development Details

A good point of reference for how to use the service programmatically would be integration_tests.py

## Advanced Message Security Details

### Message Signing
- Every message must include a valid `signature` field.
- The signature is generated using the RSA private key with PKCS#1 v1.5 padding and SHA-256 hashing.
- The signature is computed over all message fields except the `signature` field.
- Upon receipt, the service verifies the signature against available RSA public keys. Failure in verification results in an error response.

### Message Encryption
- When the `encrypt` flag is set to true, the `data` field is encrypted using AES symmetric encryption in CBC mode.
- A securely generated symmetric key is used for encryption and stored separately.
- Encrypted messages are decrypted by the service before processing, ensuring confidentiality of sensitive data.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE.md) file for details.