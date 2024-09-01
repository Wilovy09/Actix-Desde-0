use actix_multipart::form::MultipartFormConfig;
use actix_web::{App, HttpServer};
mod routes;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        const MB: usize = 1024 * 1024 * 100;
        let multipartform_config = MultipartFormConfig::default()
            .total_limit(MB)
            .memory_limit(MB);
        App::new()
            .app_data(multipartform_config)
            .configure(routes::config)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
