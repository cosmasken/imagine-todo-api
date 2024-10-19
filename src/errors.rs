use actix_web::{HttpResponse, http::StatusCode, error, http::header::ContentType};
use derive_more::{Display, Error};

#[derive(Debug, Display, Error)]
pub enum MyError {
    #[display("internal error")]
    InternalError,

    #[display("bad request")]
    BadClientData,

    #[display("timeout")]
    Timeout,

    #[display("not found")]
    NotFound,

    #[display("unauthorized")]
    Unauthorized,

    #[display("forbidden")]
    Forbidden,
}

impl error::ResponseError for MyError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code())
            .insert_header(ContentType::html())
            .body(self.to_string())
    }

    fn status_code(&self) -> StatusCode {
        match *self {
            MyError::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            MyError::BadClientData => StatusCode::BAD_REQUEST,
            MyError::Timeout => StatusCode::GATEWAY_TIMEOUT,
            MyError::NotFound => StatusCode::NOT_FOUND,
            MyError::Unauthorized => StatusCode::UNAUTHORIZED,
            MyError::Forbidden => StatusCode::FORBIDDEN,
        }
    }
}

#[derive(Debug, Display, Error)]
pub enum UserError {
    #[display("Validation error on field: {field}")]
    ValidationError { field: String },
}

impl error::ResponseError for UserError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code())
            .insert_header(ContentType::html())
            .body(self.to_string())
    }
    fn status_code(&self) -> StatusCode {
        match *self {
            UserError::ValidationError { .. } => StatusCode::BAD_REQUEST,
        }
    }
}