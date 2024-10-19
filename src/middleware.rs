use actix_web::{dev::{ServiceRequest, ServiceResponse}, Error as AWError};
use actix_service::Service;
use futures::future::LocalBoxFuture;
use crate::auth::validate_jwt;
use crate::errors::MyError;

pub async fn jwt_middleware<S>(
    req: ServiceRequest,
    next: &S
) -> Result<ServiceResponse, MyError>
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = AWError, Future = LocalBoxFuture<'static, Result<ServiceResponse, AWError>>>
{
    if let Some(auth_header) = req.headers().get("Authorization") {
        if let Ok(token) = auth_header.to_str() {
            if token.starts_with("Bearer ") {
                let token = &token[7..];
                if validate_jwt(token).is_ok() {
                    return next.call(req).await.map_err(|_| MyError::Unauthorized);
                }
            }
        }
    }
    Err(MyError::Unauthorized)
}
