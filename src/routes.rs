use actix_web::{get, post, put, delete, web, HttpResponse, Responder,HttpRequest};
use crate::{db::DbConnection, models::RegisterRequest};
use bcrypt::{hash, verify, DEFAULT_COST};
use rusqlite::params;
use crate::models::{Claims, LoginRequest, TokenResponse, TodoItem, TodoItemRequest};
use jsonwebtoken::{encode,  EncodingKey, Header};
use uuid::Uuid;
use utoipa::{OpenApi,openapi};

// JWT secret
const JWT_SECRET: &[u8] = b"your_jwt_secret"; // Replace with a secure secret


#[utoipa::path(
    post,
    path = "/register",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "User registered successfully"),
        (status = 400, description = "Bad request")
    )
)]
#[post("/register")]
async fn register(db: web::Data<DbConnection>, req: web::Json<RegisterRequest>) -> impl Responder {
    let conn = db.lock().unwrap();
    let hashed_password = hash(&req.password, DEFAULT_COST).unwrap(); // Hash the password

    match conn.execute(
        "INSERT INTO users (username, password) VALUES (?1, ?2)",
        params![req.username, hashed_password],
    ) {
        Ok(_) => HttpResponse::Created().body("User registered."),
        Err(err) => {
            HttpResponse::InternalServerError().body(format!("Failed to register user: {}", err))
        }
    }
}

#[utoipa::path(
    post,
    path = "/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "User logged in successfully", body = TokenResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Bad request")
    )
)]
//User login and token generation
#[post("/login")]
async fn login(db: web::Data<DbConnection>, req: web::Json<LoginRequest>) -> impl Responder {
    let conn = db.lock().unwrap();

    let mut stmt = conn
        .prepare("SELECT password FROM users WHERE username = ?1")
        .unwrap();
    let mut rows = stmt.query(params![req.username]).unwrap();

    if let Some(row) = rows.next().unwrap() {
        let stored_hashed_password: String = row.get(0).unwrap();

        if verify(&req.password, &stored_hashed_password).unwrap() {
            let claims = Claims {
                sub: req.username.clone(),
                exp: (chrono::Utc::now() + chrono::Duration::days(1)).timestamp() as usize,
            };
            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(JWT_SECRET),
            )
            .unwrap();

            return HttpResponse::Ok().json(TokenResponse { token });
        }
    }
    HttpResponse::Unauthorized().body("Invalid username or password")
}

// Protecting a route
#[get("/protected")]
async fn protected() -> impl Responder {
    HttpResponse::Ok().body("This is a protected route.")
}
#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("This is protected!")
}

#[post("/echo")]
async fn echo(req_body: String) -> impl Responder {
    HttpResponse::Ok().body(req_body)
}

#[utoipa::path(
    get,
    path = "/todos",
    responses(
        (status = 200, description = "List of todos", body = [TodoItem]),
        (status = 500, description = "Internal server error")
    )
)]
#[get("/todos")]
async fn get_todos(db: web::Data<DbConnection>) -> impl Responder {
    let conn = db.lock().unwrap(); // Lock the database connection

    let mut stmt = conn
        .prepare("SELECT id, title, description, due_date, status, assignee FROM tasks")
        .unwrap(); // Prepare SQL statement
    let todos_iter = stmt
        .query_map(params![], |row| {
            Ok(TodoItem {
                id: row.get(0)?, // Assuming the id is in the first column
                title: row.get(1)?,
                description: row.get(2)?,
                due_date: row.get(3)?, // Assuming due_date can be NULL
                status: row.get(4)?,
                assignee: row.get(5)?,
            })
        })
        .unwrap(); // Execute the query

    let todos_list: Vec<TodoItem> = todos_iter.filter_map(Result::ok).collect(); // Collect the results

    HttpResponse::Ok().json(todos_list) // Return the list of todos as JSON
}

#[utoipa::path(
    post,
    path = "/todos",
    request_body = TodoItemRequest,
    responses(
        (status = 201, description = "Todo added successfully"),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Unauthorized") // Respond for unauthorized users
    )
)]
#[post("/todos")]
async fn create_todo(
    db: web::Data<DbConnection>,
    req: web::Json<TodoItemRequest>,
) -> impl Responder {
    // Basic validation
    if req.title.is_empty()
        || req.status.is_empty()
        || req.description.is_empty()
        || req.assignee.is_empty()
    {
        return HttpResponse::BadRequest()
            .body("Title, Description, Status, and Assignee are required.");
    }

    // Validate status
    let valid_statuses = ["todo", "in progress", "done"];
    if !valid_statuses.contains(&req.status.as_str()) {
        return HttpResponse::BadRequest()
            .body("Invalid status. Valid statuses are: todo, in progress, done.");
    }
    let conn = db.lock().unwrap();

    let mut stmt = conn
        .prepare("SELECT COUNT(*) FROM users WHERE username = ?1")
        .unwrap();
    let count: i64 = stmt
        .query_row(params![req.assignee], |row| row.get(0))
        .unwrap_or(0);
    if count == 0 {
        return HttpResponse::NotFound().body("Assignee not found.");
    }

    let id = Uuid::new_v4().to_string();

    match conn.execute(
    "INSERT INTO tasks (id, title, description, due_date, status, assignee) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    params![id, req.title, req.description, req.due_date, req.status, req.assignee],
) {
        Ok(_) => HttpResponse::Created().body("Task added."),
        Err(err) => HttpResponse::InternalServerError().body(format!("Failed to add task: {}", err)),
    }
}

#[utoipa::path(
    get,
    path = "/todos/{id}",
    params(
        ("id" = String, Path, description = "Unique identifier of the todo item")
    ),
    responses(
        (status = 200, description = "Todo item retrieved successfully", body = TodoItem),
        (status = 404, description = "Todo item not found")
    )
)]
#[get("/todos/{id}")]
async fn get_todo_by_id(
    db: web::Data<DbConnection>,
    todo_id: web::Path<String>,
   // req: HttpRequest,
) -> impl Responder {
    let conn = db.lock().unwrap();
   // let id: String = req.match_info().get("id").unwrap().parse().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, title, description, due_date, status, assignee FROM tasks WHERE id = ?1",
        )
        .unwrap();

    if let Ok(row) = stmt.query_row(params![todo_id.into_inner()], |row| {
        Ok(TodoItem {
            id: row.get(0)?,
            title: row.get(1)?,
            description: row.get(2)?,
            due_date: row.get(3)?,
            status: row.get(4)?,
            assignee: row.get(5)?,
        })
    }) {
        HttpResponse::Ok().json(row)
    } else {
        HttpResponse::NotFound().body("Todo item not found")
    }
}

//assuming assignee can be updated
#[utoipa::path(
    put,
    path = "/todos/{id}",
    request_body = TodoItemRequest,
    params(
        ("id" = String, Path, description = "Unique identifier of the todo item")
    ),
    responses(
        (status = 200, description = "Todo item updated successfully", body = TodoItem),
        (status = 404, description = "Todo item not found"),
        (status = 400, description = "Bad request")
    )
)]
#[put("/todos/{id}")]
async fn edit_todo_by_id(
    db: web::Data<DbConnection>,
    todo_id: web::Path<String>,
    update_data: web::Json<TodoItemRequest>,
) -> impl Responder {
    let conn = db.lock().unwrap();

    // Validate status
    let valid_statuses = ["todo", "in progress", "done"];
    if !valid_statuses.contains(&update_data.status.as_str()) {
        return HttpResponse::BadRequest()
            .body("Invalid status. Valid statuses are: todo, in progress, done.");
    }

    // Check if the assignee exists
    let mut stmt = conn
        .prepare("SELECT COUNT(*) FROM users WHERE username = ?1")
        .unwrap();
    let count: i64 = stmt
        .query_row(params![update_data.assignee], |row| row.get(0))
        .unwrap_or(0);
    if count == 0 {
        return HttpResponse::NotFound().body("Assignee not found.");
    }

    // Update the todo item in the database
    match conn.execute(
        "UPDATE tasks SET title = ?1, description = ?2, due_date = ?3, status = ?4, assignee = ?5 WHERE id = ?6",
        params![update_data.title, update_data.description, update_data.due_date, update_data.status, update_data.assignee, todo_id.into_inner()],
    ) {
        Ok(updated_rows) if updated_rows > 0 => {
            HttpResponse::Ok().body("Todo item updated successfully.")
        }
        _ => HttpResponse::NotFound().body("Todo item not found"),
    }
}

#[utoipa::path(
    put,
    path = "/todos/{id}",
    request_body = TodoItemRequest,
    params(
        ("id" = String, Path, description = "Unique identifier of the todo item")
    ),
    responses(
        (status = 200, description = "Todo item updated successfully", body = TodoItem),
        (status = 404, description = "Todo item not found")
    )
)]
#[put("/todos/{id}")]
async fn update_todo(
    db: web::Data<DbConnection>,
    todo_id: web::Path<String>,
    update_data: web::Json<TodoItemRequest>,
) -> impl Responder {
    let conn = db.lock().unwrap();

    match conn.execute(
        "UPDATE tasks SET title = ?1, description = ?2, due_date = ?3, status = ?4 WHERE id = ?5",
        params![
            update_data.title,
            update_data.description,
            update_data.due_date,
            update_data.status,
            todo_id.into_inner()
        ],
    ) {
        Ok(updated_rows) if updated_rows > 0 => {
            HttpResponse::Ok().body("Todo item updated successfully.")
        }
        _ => HttpResponse::NotFound().body("Todo item not found"),
    }
}

#[utoipa::path(
    delete,
    path = "/todos/{id}",
    params(
        ("id" = String, Path, description = "Unique identifier of the todo item")
    ),
    responses(
        (status = 204, description = "Todo item deleted successfully"),
        (status = 404, description = "Todo item not found")
    )
)]
#[delete("/todos/{id}")]
async fn delete_todo(
    db: web::Data<DbConnection>,
    todo_id: web::Path<String>, // Using String here since ID is stored as TEXT in the database
) -> impl Responder {
    let conn = db.lock().unwrap();

    match conn.execute(
        "DELETE FROM tasks WHERE id = ?1",
        params![todo_id.into_inner()],
    ) {
        Ok(rows_deleted) => {
            if rows_deleted > 0 {
                HttpResponse::NoContent().finish() // No content indicates successful deletion
            } else {
                HttpResponse::NotFound().body("Todo item not found") // Item not found
            }
        }
        Err(err) => {
            HttpResponse::InternalServerError().body(format!("Failed to delete task: {}", err))
        } // Handle error
    }
}

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/html")
        .body(include_str!("../static/index.html"))
}


#[derive(OpenApi)]
#[openapi(
    paths(get_todos, edit_todo_by_id,get_todo_by_id, create_todo, register, login),
    components(schemas(TodoItem, TodoItemRequest, RegisterRequest, LoginRequest, TokenResponse))
)]
pub struct ApiDoc;
