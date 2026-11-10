# Project 2 – SecureNova AI Identity Implementation

## Overview

This project implements identity and access management controls for the SecureNova AI Chat application. It uses Java, Spring Boot, Spring Security and Auth0 to protect application endpoints and validate authenticated requests.

## Technology Stack

- Java 21
- Spring Boot
- Spring Security
- OAuth 2.0 / OpenID Connect
- Auth0
- Maven

## Implementation

The application includes the following security components:

1. Auth0-based user authentication.
2. OAuth 2.0 Authorization Code flow with PKCE for user login.
3. JWT validation for protected API requests.
4. Scope-based authorization for API and administrative endpoints.
5. A user information endpoint for retrieving authenticated user details.

## Access Control

The implementation separates access to application resources according to assigned permissions.

- The `/chat` API requires the `read.ai-data` scope.
- The `/admin` API requires the `write:admin` scope.

Requests are validated before access to protected resources is granted.

## Project Structure

- `src/main/java/` – Java application source code.
- `src/main/resources/` – Application configuration and web resources.
- `src/test/` – Test source files.
- `.mvn/` – Maven Wrapper configuration.
- `mvnw` and `mvnw.cmd` – Maven Wrapper scripts.
- `pom.xml` – Maven dependencies and build configuration.

## Security Note

Environment-specific configuration and credentials must be managed securely. No client secrets, API keys, passwords or access tokens should be committed to this repository.

## Project Scope

This repository contains the implementation and supporting configuration developed for the SecureNova AI Identity Security Capstone. It represents a controlled project implementation and should not be interpreted as a production security certification.