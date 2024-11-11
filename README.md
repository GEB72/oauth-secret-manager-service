# oauth-secret-manager-service

## Overview

The OAuth Secret Manager Service is a Go-based application designed for secure management of OAuth secrets and keys using AWS Secrets Manager and AWS KMS. It provides functionalities for creating, retrieving, updating, and resolving secrets, which are critical for facilitating secure OAuth workflows. The service is designed to run within a Docker container, typically hosted on an AWS EC2 instance with the necessary permissions and keys stored in the environment.

## Features

* Secure storage and retrieval of secrets using AWS Secrets Manager.
* Encryption and decryption of keys using AWS KMS.
* JWT-based authentication middleware for added security.
* Dynamic resolution of secrets based on root domain, user ID, and domain using `SMS_ROOT_DOMAIN`.

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
export KMS_KEY_ID=your-kms-key-id
export REGION=your-aws-region
export SMS_ROOT_DOMAIN=your-root-domain
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
    - Method: **POST**
    - Headers:
        - `Authorization`: Bearer token containing the JWT.
    - Body (JSON):
      ```json
      {
        "user_id": "1"
      }
      ```

- **For `/token/save` Endpoint**:
    - Method: **POST**
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

### Available Endpoints

* **`/token/get`**: Retrieves a token for a given user.
* **`/token/save`**: Saves a token with a specified user ID and related metadata.

Refer to the API documentation for detailed information on all available endpoints and their usage.

## Testing

Unit tests are available for core functionality. Run tests using:

```bash
go test ./...
```

