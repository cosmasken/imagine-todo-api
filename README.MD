# Imagine Todo API

## Project Overview

**Imagine Todo API** is a simple RESTful API designed for task management. The API allows users to create, read, update, and delete tasks. Each task includes a title, description, due date, and status (e.g., "todo," "in progress," or "done"). Additionally, users can filter tasks by status and due date.

### Objectives

- **Task Management**: Users can manage tasks effectively with CRUD operations.
- **User Authentication**: Implement token-based authentication for secure access to the API.
- **Task Filtering**: Enable filtering of tasks based on their status and due dates.

## Requirements

- Implement proper data validation and error handling.
- Support for user authentication with registration and login capabilities.
- Create and manage tasks with the following endpoints:
  - **User Management**:
    - Create a new user account.
    - Obtain a token by providing valid credentials.
  - **Task Management**:
    - Create a new task.
    - Retrieve a list of all tasks.
    - Retrieve details of a specific task by its ID.
    - Edit a specific task by its ID.
    - Delete a specific task by its ID.
- **Bonus**: 
  - Task Assignment: Implement an "assignee" field to refer to the user responsible for completing the task.
  - User Roles: Differentiate between regular users and admin users. Admins can view, update, and delete any task, while regular users can only manage their assigned tasks.

## Tools

- **Backend Framework**: Actix-web
- **Database**: Rusqlite

## Evaluation Criteria

- **Functionality**: The API must meet the specified requirements and operate correctly without significant bugs.
- **Code Quality**: Code should be well-structured, readable, maintainable, and adhere to best practices.
- **Error Handling**: The API should handle errors gracefully and provide informative feedback to users.

## Getting Started

### Prerequisites

- Ensure you have the following installed:
  - [Rust](https://www.rust-lang.org/) (with Cargo)
  - [SQLite](https://www.sqlite.org/) (if using Rusqlite)

### Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/cosmasken/imagine-todo-api.git
   cd imagine-todo-api
2. **Install Dependencies**
    ```bash
   cargo build

3. **Install Dependencies**
    ```bash
   cargo run

**API Endpoints**
Here are the key API endpoints you can use:

**User Management**
POST /register: Create a new user account.
POST /login: Obtain a token by providing valid credentials.
**Task Management**
POST /tasks: Create a new task.
GET /tasks: Retrieve a list of all tasks.
GET /tasks/{id}: Retrieve details of a specific task by its ID.
PUT /tasks/{id}: Edit a specific task by its ID.
DELETE /tasks/{id}: Delete a specific task by its ID.

**Usage Examples**
**Register a User**
    ```bash
    curl -X POST http://localhost:8080/register \
    -H "Content-Type: application/json" \
    -d '{"username": "testuser", "password": "testpass"}'
**Login a User**
```bash
curl -X POST http://localhost:8080/login \
-H "Content-Type: application/json" \
-d '{"username": "testuser", "password": "testpass"}'
**Create a New Task**
bash
curl -X POST http://localhost:8080/tasks \
-H "Authorization: Bearer YOUR_TOKEN" \
-H "Content-Type: application/json" \
-d '{"title": "Test Task", "description": "Description for the test task", "due_date": "2024-12-31", "status": "todo"}'
**Retrieve All Tasks**
bash
curl -X GET http://localhost:8080/tasks \
-H "Authorization: Bearer YOUR_TOKEN"