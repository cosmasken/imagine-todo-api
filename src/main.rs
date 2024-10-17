use actix_web::{get, post, put, delete, middleware, web, App, HttpResponse, HttpServer, Responder};
use utoipa_swagger_ui::SwaggerUi;
use jsonwebtoken::{encode, decode, Header ,EncodingKey};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::collections::HashMap;
use uuid::Uuid;
use dotenv::dotenv;
use env_logger;
use log::info;
use rusqlite::{params, Connection};
use bcrypt::{DEFAULT_COST, hash, verify};
use actix_files::Files;
use utoipa::{{OpenApi,ToSchema}};
use std::time::Duration;
use chrono::{DateTime, Utc};


#[derive(Serialize, Deserialize, Clone)]
struct User {
    username: String,
    password: String,
}

#[derive(Deserialize,ToSchema)]
struct RegisterRequest {
    username: String,
    password: String,
}

#[derive(Deserialize,ToSchema)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize, ToSchema)]
struct TokenResponse {
    token: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
struct TodoItem {
    #[schema(value_type = String, example = "550e8400-e29b-41d4-a716-446655440000")]
    id : Uuid,
    title: String,
    description: String,
    due_date: Option<String>, // Use Option<String> for optional due date
    status: String, // e.g., "todo", "in progress", "done"
}

type TodoList = Mutex<HashMap<Uuid, TodoItem>>;
// In-memory user storage
//type UserStorage = Mutex<HashMap<String, String>>; // Map of username to hashed password

// JWT secret
const JWT_SECRET: &[u8] = b"your_jwt_secret"; // Replace with a secure secret

// Use a Mutex to wrap the Connection for thread-safe access
type DbConnection = Mutex<Connection>;
// Initialize the database
fn init_db() -> DbConnection {
    let conn = Connection::open("todo.db").unwrap();
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )",
        [],
    ).unwrap();

    conn.execute(
        "CREATE TABLE IF NOT EXISTS tasks (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            due_date TEXT NOT NULL,
            status TEXT NOT NULL
        )",
        [],
    ).unwrap();

  //  conn
  Mutex::new(conn) // Wrap the Connection in a Mutex and return
}
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
        Err(err) => HttpResponse::InternalServerError().body(format!("Failed to register user: {}", err)),
    }
}
// #[post("/register")]
// async fn register(db: web::Data<DbConnection>, req: web::Json<RegisterRequest>) -> impl Responder {
//     let hashed_password = hash(&req.password,DEFAULT_COST).unwrap(); // Hash the password
//     db.execute(
//         "INSERT INTO users (username, password) VALUES (?1, ?2)",
//         params![req.username, hashed_password],
//     ).unwrap();
//     HttpResponse::Created().body("User registered.")
// }

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

    let mut stmt = conn.prepare("SELECT password FROM users WHERE username = ?1").unwrap();
    let mut rows = stmt.query(params![req.username]).unwrap();

    if let Some(row) = rows.next().unwrap() {
        let stored_hashed_password: String = row.get(0).unwrap();

        if verify(&req.password, &stored_hashed_password).unwrap() {
            let claims = Claims {
                sub: req.username.clone(),
                exp: (chrono::Utc::now() + chrono::Duration::days(1)).timestamp() as usize,
            };
            let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(JWT_SECRET))
                .unwrap();

            return HttpResponse::Ok().json(TokenResponse { token });
        }
    }
    HttpResponse::Unauthorized().body("Invalid username or password")
}
// #[post("/login")]
// async fn login(db: web::Data<DbConnection>, req: web::Json<LoginRequest>) -> impl Responder {
//     // Retrieve the user from the database
//     let mut stmt = db.prepare("SELECT password FROM users WHERE username = ?1").unwrap();
//     let mut rows = stmt.query(params![req.username]).unwrap();

//     if let Some(row) = rows.next().unwrap() {
//         let stored_hashed_password: String = row.get(0).unwrap();

//         // Verify the password
//         if verify(&req.password, &stored_hashed_password).unwrap() {
//             // Generate a JWT token
//             let claims = Claims {
//                 sub: req.username.clone(),
//                 exp: (chrono::Utc::now() + chrono::Duration::days(1)).timestamp() as usize,
//             };
//             let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(JWT_SECRET))
//                 .unwrap();

//             // Return the token as a response
//             return HttpResponse::Ok().json(TokenResponse { token });
//         }
//     }

//     // If authentication fails
//     HttpResponse::Unauthorized().body("Invalid username or password")
// }

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

// Protecting a route
#[get("/protected")]
async fn protected() -> impl Responder {
    HttpResponse::Ok().body("This is a protected route.")
}
#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

#[post("/echo")]
async fn echo(req_body: String) -> impl Responder {
    HttpResponse::Ok().body(req_body)
}

#[utoipa::path(
    get,
    path = "/todos",
    responses(
        (status = 200, description = "Get all todos", body = [TodoItem])
    )
)]
#[get("/todos")]
async fn get_todos(data: web::Data<TodoList>) -> impl Responder {
    let todos = data.lock().unwrap();
    let todos_list: Vec<&TodoItem> = todos.values().collect();
    HttpResponse::Ok().json(todos_list)
}
// #[get("/todos")]
// async fn get_todos(
//     data: web::Data<TodoList>,
//     status: Option<String>,
//     due_date: Option<String>,
// ) -> impl Responder {
//     let todos = data.lock().unwrap();
//     let filtered_todos: Vec<&TodoItem> = todos.values()
//         .filter(|todo| {
//             (status.is_none() || Some(todo.status.clone()) == status) &&
//             (due_date.is_none() || Some(todo.due_date.clone()) == due_date)
//         })
//         .collect();
//     HttpResponse::Ok().json(filtered_todos)
// }

#[utoipa::path(
    post,
    path = "/todos",
    request_body = TodoItemRequest,
    responses(
        (status = 201, description = "Create a new todo", body = TodoItem)
    )
)]
#[post("/todos")]
async fn create_todo(
    data: web::Data<TodoList>,
    new_todo: web::Json<TodoItemRequest>,
) -> impl Responder {
    // Basic validation
    if new_todo.title.is_empty() || new_todo.status.is_empty() {
        return HttpResponse::BadRequest().body("Title and status are required.");
    }
    
    // Validate status
    let valid_statuses = ["todo", "in progress", "done"];
    if !valid_statuses.contains(&new_todo.status.as_str()) {
        return HttpResponse::BadRequest().body("Invalid status. Valid statuses are: todo, in progress, done.");
    }

    let mut todos = data.lock().unwrap();
    let todo_item = TodoItem {
        id: Uuid::new_v4(),
        title: new_todo.title.clone(),
        description: new_todo.description.clone(),
        due_date: new_todo.due_date.clone(),
        status: new_todo.status.clone(),
    };
    todos.insert(todo_item.id, todo_item.clone());
    
    // Log the new todo item
    info!("Creating new todo: {:?}", todo_item);
    
    HttpResponse::Created().json(todo_item)
}

#[derive(OpenApi)]
#[openapi(
    paths(get_todos, create_todo, register, login),
    components(schemas(TodoItem, TodoItemRequest, RegisterRequest, LoginRequest, TokenResponse))
)]
struct ApiDoc;

async fn manual_hello() -> impl Responder {
    HttpResponse::Ok().body("Hey there!")
}

#[derive(Deserialize, ToSchema)]
struct TodoItemRequest {
    title: String,
    description: String,
    due_date: Option<String>,
    status: String, // e.g., "todo", "in progress", "done"
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
async fn get_todo_by_id(data: web::Data<TodoList>, todo_id: web::Path<Uuid>) -> impl Responder {
    let todos = data.lock().unwrap();
    if let Some(todo_item) = todos.get(&todo_id.into_inner()) {
        HttpResponse::Ok().json(todo_item.clone())
    } else {
        HttpResponse::NotFound().body("Todo item not found")
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
async fn edit_todo_by_id(
    data: web::Data<TodoList>,
    todo_id: web::Path<Uuid>,
    update_data: web::Json<TodoItemRequest>,
) -> impl Responder {
    let mut todos = data.lock().unwrap();
    if let Some(todo_item) = todos.get_mut(&todo_id.into_inner()) {
        todo_item.title = update_data.title.clone();
        todo_item.description = update_data.description.clone();
        todo_item.due_date = update_data.due_date.clone();
        todo_item.status = update_data.status.clone();
        HttpResponse::Ok().json(todo_item.clone())
    } else {
        HttpResponse::NotFound().body("Todo item not found")
    }
}


#[put("/todos/{id}")]
async fn update_todo(
    data: web::Data<TodoList>,
    todo_id: web::Path<Uuid>,
    update_data: web::Json<TodoItemRequest>,
) -> impl Responder {
    let mut todos = data.lock().unwrap();
    if let Some(todo_item) = todos.get_mut(&todo_id.into_inner()) {
        todo_item.title = update_data.title.clone();
        todo_item.description = update_data.description.clone();
        todo_item.due_date = update_data.due_date.clone();
        todo_item.status = update_data.status.clone();
        HttpResponse::Ok().json(todo_item.clone())
    } else {
        HttpResponse::NotFound().body("Todo item not found")
    }
}

#[delete("/todos/{id}")]
async fn delete_todo(
    data: web::Data<TodoList>,
    todo_id: web::Path<Uuid>,
) -> impl Responder {
    let mut todos = data.lock().unwrap();
    if todos.remove(&todo_id.into_inner()).is_some() {
        HttpResponse::NoContent().finish()
    } else {
        HttpResponse::NotFound().body("Todo item not found")
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize the logger
    env_logger::init();
    let todo_list = web::Data::new(TodoList::new(HashMap::new()));
  //  let user_storage = web::Data::new(UserStorage::new(HashMap::new()));
    // Optional: Log a message to confirm the server is starting
    info!("Starting Actix Web server on http://127.0.0.1:8080");

    dotenv().ok(); // Load environment variables from .env file
    let db = init_db();
    let db_data = web::Data::new(db);
    
    HttpServer::new(move || {
        App::new()
        
            .app_data(todo_list.clone())
           // .app_data(user_storage.clone())
            .app_data(db_data.clone())
            .wrap(middleware::Logger::default())
            .service(
                SwaggerUi::new("/swagger-ui/{_:.*}")
                    .url("/api-doc/openapi.json", ApiDoc::openapi()),
            )
            .service(Files::new("/static", "static/").prefer_utf8(true))
            .service(register)
            .service(login)
            .service(protected) // Add protected endpoint
            .service(get_todos)
            .service(create_todo)
            .service(get_todo_by_id)
            .service(edit_todo_by_id)
            .service(update_todo)
            .service(delete_todo)
            .service(index)
            .service(web::scope("").route("/hey", web::get().to(manual_hello)))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}


#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().content_type("text/html").body(include_str!("../static/index.html"))
}

// curl -X POST http://127.0.0.1:8080/todos -H "Content-Type: application/json" -d '{"title": "Build a Web API", "description": "Create a RESTful API using Actix.", "due_date": "2024-10-25", "status": "in progress"}'

