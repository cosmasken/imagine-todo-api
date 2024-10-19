use serde::{Serialize, Deserialize};
use utoipa::{ToSchema};

#[derive(Serialize, Deserialize, Clone)]
pub struct User {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize, ToSchema)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
}

#[derive( Deserialize, ToSchema)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}   
    
#[derive(Serialize, ToSchema)]
pub struct TokenResponse {
    pub token: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct TodoItem {
    // #[schema(value_type = String, example = "550e8400-e29b-41d4-a716-446655440000")]
    pub id: String,
    pub title: String,
    pub description: String,
    pub due_date: Option<String>,
    pub status: String, // e.g., "todo", "in progress", "done"
    pub assignee: String,
}


#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}



#[derive(Deserialize, ToSchema)]
pub struct TodoItemRequest {
    pub title: String,
    pub description: String,
    pub due_date: Option<String>,
    pub status: String,
    pub assignee: String,
}

