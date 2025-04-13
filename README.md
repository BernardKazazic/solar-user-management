# solar-user-management

## About solar-user-management service
This service is used for management of users, roles and permissions in project ecosystem. Service communicates with auth0 management API to achieve this since we are using auth0 for the project. It is written in Java with reactive Spring boot.

## Relationships with other services

### API Gateway
solar-user-management service receives requests exclusively from API Gateway. API Gateway is used to connect all services in the system to UI. API Gateway also checks if users are authorized to use some endpoint. Authorization is based on auth0 permissions. It is also implemented in Java with reactive Spring Boot. It uses Spring Cloud Gateway.

### UI
Relevant UI function to this service is user management trough solar-user-management service.