# oauth-secret-manager-service

## Overview

The OAuth Secret Manager Service is a Go-based application designed for secure management of OAuth secrets and keys using AWS Secrets Manager and AWS KMS. It provides functionalities for creating, retrieving, updating, and resolving secrets, which are critical for facilitating secure OAuth workflows. The service is designed to run within a Docker container, typically hosted on an AWS EC2 instance with the necessary permissions and keys stored in the environment.

## Features

* Secure storage and retrieval of secrets using AWS Secrets Manager.
* Encryption and decryption of keys using AWS KMS.
* JWT-based authentication middleware for added security.

## Prerequisites

* Go 1.23.2 or higher.
* AWS CLI configured with appropriate permissions.
* Docker installed on your machine or server.
* An AWS EC2 instance with the necessary IAM role and policies to access AWS Secrets Manager and AWS KMS.

## Installation

### Clone the Repository

```bash
git clone https://github.com/stackedtracker/oauth-secret-manager-service.git
cd oauth-secret-manager-service
```

### Install Dependencies

Ensure you have the required Go modules installed:

```bash
go mod tidy
```

### Configuration

Set up the necessary environment variables:

```bash
export AWS_ACCESS_KEY_ID=your-access-key-id
export AWS_SECRET_ACCESS_KEY=your-secret-access-key
export SMS_ROOT_DOMAIN=your-root-domain
export KMS_KEY_ID=your-kms-key-id
export REGION=your-aws-region
```

* **`AWS_ACCESS_KEY_ID`** and **`AWS_SECRET_ACCESS_KEY`**: AWS credentials with appropriate permissions.
* **`KMS_KEY_ID`**: The AWS KMS key ID used for key encryption and decryption.
* **`REGION`**: AWS region where the service will operate.
* **`SMS_ROOT_DOMAIN`**: This variable defines the root domain for the secrets. It forms part of the secret ID, allowing secrets to be logically grouped and resolved.

Consider using a `.env` file to manage environment variables securely. **Do not commit this file to version control.**

## Usage

### Running the Service Locally

To start the service locally:

```bash
go run .\cmd\main\main.go
```

### Using Docker

The service is designed to be containerized and run within a Docker container, hosted on an EC2 instance with the necessary permissions. The EC2 instance should have an attached IAM role with policies granting access to AWS Secrets Manager and AWS KMS.

#### Build the Docker Image

```bash
docker build -t oauth-secret-manager-service .
```

#### Run the Docker Container

```bash
docker run -e AWS_ACCESS_KEY_ID=your-access-key-id \
           -e AWS_SECRET_ACCESS_KEY=your-secret-access-key \
           -e KMS_KEY_ID=your-kms-key-id \
           -e REGION=your-aws-region \
           -e SMS_ROOT_DOMAIN=your-root-domain \
           -p 8080:8080 oauth-secret-manager-service
```

**Note**: When running on an EC2 instance with an IAM role, you can omit `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` if the role has sufficient permissions.

### AWS Permissions and Setup

1. Ensure the EC2 instance has an IAM role attached with policies to access AWS Secrets Manager and AWS KMS.
2. Use `SMS_ROOT_DOMAIN` to define the root domain for secrets. The service uses this variable to construct unique secret IDs in the format:
   ```
   <SMS_ROOT_DOMAIN>/<Domain>/<UserID>
   ```

### JWT Verification Using JWK

The service utilizes **JSON Web Tokens (JWT)** and **JSON Web Key (JWK)** for secure communication and authentication of incoming requests. The **JWK** is used for verifying the signature of incoming JWTs. Here’s how it works in the context of the service:

1. **JWK Storage**: The public key used for JWT verification is stored and managed using AWS KMS (Key Management Service). The corresponding JWK can be retrieved from AWS KMS when needed.
2. **JWT Validation**: Incoming requests must provide a JWT, typically passed as a **Bearer token** in the `Authorization` header. The JWT is validated using the JWK to ensure the integrity and authenticity of the token.

#### Incoming Request Structure

**Headers**
- **`Authorization`**: Incoming requests must include an `Authorization` header containing the JWT as a Bearer token.
  ```
  Authorization: Bearer <your-jwt-token>
  ```

**JWT Payload (Example)**
- A typical JWT payload may include claims such as:
  ```json
  {
    "sub": "1"
  }
  ```

**Expected Request Format**
- **For `/token/get` Endpoint**:
    - Method: **GET**
    - Headers:
        - `Authorization`: Bearer token containing the JWT.
    - Body (JSON):
      ```json
      {
        "user_id": "1"
      }
      ```

- **For `/token/save` Endpoint**:
    - Method: **PUT**
    - Headers:
        - `Authorization`: Bearer token containing the JWT.
    - Body (JSON):
      ```json
      {
        "user_id": "1",
        "access_token": "blah",
        "refresh_token": "bloo",
        "expiry": "2026-01-02T15:04:05Z" 
      }
      ```

**Security Considerations**
- Ensure the JWT is signed using the appropriate algorithm (e.g., `RS256`) that matches the public key in the JWK retrieved from AWS KMS.
- Validate all incoming JWTs for:
    - **Signature**: The token must be verified using the JWK.
    - **Claims**: Check claims like `sub` (subject) and `exp` (expiration) to ensure the token is valid and has not expired.
- **Use HTTPS**: All communication with the service should be done over HTTPS to prevent token interception.


### Enabling HTTPS with a Reverse Proxy

To enhance security, you can set up a **reverse proxy** (e.g., Nginx or AWS Application Load Balancer) in front of your service to handle HTTPS. The reverse proxy will:
1. Terminate SSL/TLS connections and handle HTTPS traffic.
2. Forward requests to your service over HTTP.
3. Redirect all HTTP traffic to HTTPS, ensuring secure communication.

#### Example Nginx Configuration

```nginx
server {
    listen 80;
    server_name your-domain.com;

    # Redirect HTTP to HTTPS
    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name your-domain.com;

    # SSL Configuration
    ssl_certificate /etc/nginx/self-signed.crt;  # Path to your SSL cert
    ssl_certificate_key /etc/nginx/self-signed.key;  # Path to your SSL key

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://localhost:8080;  # Forward requests to localhost
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

This configuration will:
- Redirect all HTTP traffic to HTTPS.
- Forward HTTPS requests to your service running on `localhost:8080`.

### Available Endpoints

* **`/token/get`**: Retrieves a token for a given user.
* **`/token/save`**: Saves a token with a specified user ID and related metadata.

Refer to the API documentation for detailed information on all available endpoints and their usage.

## Testing

Unit tests are available for core functionality. Run tests using:

```bash
go test ./...
```

