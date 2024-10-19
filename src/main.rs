use actix_web::{App, HttpServer, middleware, web};
use utoipa::{openapi,OpenApi};
use utoipa_swagger_ui::SwaggerUi;
use imagine_todo_api::ApiDoc;
use imagine_todo_api::{register, login, get_todos, create_todo, edit_todo_by_id, get_todo_by_id,  init_db}; // Routes and functions

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let db = init_db();
    let db_data = web::Data::new(db);

    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
           // .wrap_fn(jwt_middleware)
            .app_data(db_data.clone())
            .service(
                SwaggerUi::new("/swagger-ui/{_:.*}")
                    .url("/api-doc/openapi.json", ApiDoc::openapi()),
            )
            .service(register)
            .service(login)
            .service(get_todos)
            .service(create_todo)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}


