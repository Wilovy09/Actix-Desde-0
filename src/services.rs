use crate::AppState;
use actix_web::{
    get, post,
    web::{Data, Json, Path},
    HttpResponse, Responder,
};
use serde::{Deserialize, Serialize};
use sqlx::{self, FromRow};

#[derive(Serialize, FromRow)]
struct User {
    id: i32,
    name: String,
    last_name: String,
}

#[derive(Serialize, FromRow)]
struct Article {
    id: i32,
    title: String,
    content: String,
    created_by: i32,
}

#[derive(Deserialize)]
pub struct CreateUserBody {
    name: String,
    last_name: String,
}

#[derive(Deserialize)]
pub struct CreateArticleBody {
    pub title: String,
    pub content: String,
}

#[get("/users")]
async fn fetch_users(state: Data<AppState>) -> impl Responder {
    match sqlx::query_as::<_, User>("SELECT id, name, last_name FROM users")
        .fetch_all(&state.db)
        .await
    {
        Ok(users) => HttpResponse::Ok().json(users),
        Err(_) => HttpResponse::NotFound().json("No users found"),
    }
}

#[post("/users")]
async fn create_user(state: Data<AppState>, body: Json<CreateUserBody>) -> impl Responder {
    match sqlx::query_as::<_, User>(
        "INSERT INTO users (name, last_name) VALUES ($1, $2) RETURNING id, name, last_name",
    )
    .bind(body.name.to_string())
    .bind(body.last_name.to_string())
    .fetch_one(&state.db)
    .await
    {
        Ok(users) => HttpResponse::Ok().json(users),
        Err(_) => HttpResponse::InternalServerError().json("Error to create a new user"),
    }
}

#[get("/users/{id}/articles")]
async fn fetch_user_articles(path: Path<i32>, state: Data<AppState>) -> impl Responder {
    let id: i32 = path.into_inner();

    match sqlx::query_as::<_, Article>(
        "SELECT id, title, content, created_by WHERE created_by = $1",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await
    {
        Ok(articles) => HttpResponse::Ok().json(articles),
        Err(_) => HttpResponse::NotFound().json("No articles found"),
    }
}

#[post("/users/{id}/articles")]
async fn create_user_article(
    path: Path<i32>,
    body: Json<CreateArticleBody>,
    state: Data<AppState>,
) -> impl Responder {
    let id: i32 = path.into_inner();

    match sqlx::query_as::<_, Article>("INSERT INTO articles (title, content, created_by) VALUES ($1, $2, $3) RETURNING id, title, content, created_by")
        .bind(body.title.to_string())
        .bind(body.content.to_string())
        .bind(id)
        .fetch_one(&state.db)
        .await
    {
        Ok(article) => HttpResponse::Ok().json(article),
        Err(_) => HttpResponse::InternalServerError().json("Failed to create user article")
    }
}
