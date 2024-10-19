use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, Algorithm};
use crate::errors::MyError;
use crate::models::Claims;

const JWT_SECRET: &[u8] = b"your_jwt_secret";

pub fn create_jwt(user_id: &str) -> String {
    let claims = Claims {
        sub: user_id.to_string(),
        exp: (chrono::Utc::now() + chrono::Duration::days(1)).timestamp() as usize,
    };

    encode(&Header::default(), &claims, &EncodingKey::from_secret(JWT_SECRET)).unwrap()
}

pub fn validate_jwt(token: &str) -> Result<Claims, MyError> {
    decode::<Claims>(token, &DecodingKey::from_secret(JWT_SECRET), &Validation::new(Algorithm::HS256))
        .map(|data| data.claims)
        .map_err(|_| MyError::Unauthorized)
}
