use actix_web::{
    dev::ServiceRequest,
    error::{self},
    get, post, web, App, Error, HttpResponse, HttpServer,
};
use actix_web_grants::authorities::AttachAuthorities;
use actix_web_grants::protect;
use actix_web_httpauth::{
    extractors::bearer::{BearerAuth, Config as BearerConfig},
    middleware::HttpAuthentication,
};
use chrono::{Duration, Utc};
use dotenv::dotenv;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::env;
// -------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug)]
struct Claims {
    iss: String,
    sub: String,
    exp: usize,
    iat: usize,
    tipo: String,
    user_id: usize,
}

#[derive(Serialize, Deserialize)]
struct LoginForm {
    usuario: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
struct LoginResult {
    token: String,
    refresh: String,
}

#[derive(Serialize, Deserialize)]
struct RefreshResult {
    token: String,
}
// -------------------------------------------------------------------------------
fn get_secret_key() -> String {
    dotenv().ok();
    let secret_key = env::var("SECRET_KEY").expect("SECRET_KEY must be set");
    secret_key
}

fn generar_token(
    iss: String,
    sub: String,
    duracion_en_minutos: i64,
    user_id: usize,
    tipo: String,
) -> String {
    let header = Header::new(Algorithm::HS512);
    let encoding_key = EncodingKey::from_secret(get_secret_key().as_bytes());

    let exp = (Utc::now() + Duration::minutes(duracion_en_minutos)).timestamp() as usize;
    let iat = Utc::now().timestamp() as usize;

    let my_claims = Claims {
        iss,
        sub,
        exp,
        iat,
        tipo,
        user_id,
    };

    encode(&header, &my_claims, &encoding_key).unwrap()
}

fn validar_token(token: String) -> Result<Claims, jsonwebtoken::errors::Error> {
    let validacion = Validation::new(Algorithm::HS512);
    let decoding_key = DecodingKey::from_secret(get_secret_key().as_bytes());

    let resultado = decode::<Claims>(&token, &decoding_key, &validacion);
    match resultado {
        Ok(c) => {
            println!("Token es valido");
            Ok(c.claims)
        }
        Err(e) => {
            println!("Token es invalido");
            Err(e)
        }
    }
}

async fn validador(
    req: ServiceRequest,
    credenciales: Option<BearerAuth>,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let Some(credenciales) = credenciales else {
        return Err((error::ErrorBadRequest("No se especifico el token"), req));
    };

    let token = credenciales.token();
    let resultado = validar_token(token.to_owned());
    match resultado {
        Ok(claims) => {
            if claims.tipo != "refresh" {
                if claims.user_id == 1 {
                    req.attach(vec!["DIRECTOR".to_string(), "LOG_IN".to_string()]);
                }
                if claims.user_id == 2 {
                    req.attach(vec!["GERENTE".to_string(), "LOG_IN".to_string()]);
                }
                return Ok(req);
            }
            Err((error::ErrorForbidden("No tiene acceso"), req))
        }
        Err(_) => Err((error::ErrorForbidden("No tiene acceso"), req)),
    }
}
// -------------------------------------------------------------------------------
#[post("/login")]
async fn login(form: web::Form<LoginForm>) -> HttpResponse {
    if form.usuario == "Wilovy" && form.password == "Test12345." {
        let iss = "Rust JWT".to_owned();
        let sub = "Prueba".to_owned();
        let duracion_en_minutos: i64 = 5;
        let duracion_dia: i64 = 1440;
        let user_id = 2;
        let token = generar_token(
            iss.clone(),
            sub.clone(),
            duracion_en_minutos,
            user_id,
            "token-normal".to_owned(),
        );
        let refresh = generar_token(
            iss.clone(),
            sub.clone(),
            duracion_dia,
            user_id,
            "refresh".to_owned(),
        );

        let respuesta = LoginResult { token, refresh };
        HttpResponse::Ok().json(respuesta)
    } else {
        HttpResponse::Unauthorized().body("Login invalido")
    }
}

#[post("/refresh-token")]
async fn refresh_token(refresh_jwt: Option<BearerAuth>) -> HttpResponse {
    let Some(refresh_jwt) = refresh_jwt else {
        return HttpResponse::Forbidden().body("Token no enviado");
    };

    let claims = validar_token(refresh_jwt.token().to_owned());

    match claims {
        Ok(c) => {
            // Crear el nuevo token-normal
            if c.tipo == "refresh" {
                let iss = c.iss.to_owned();
                let sub = c.sub.to_owned();
                let duracion_en_minutos = 5;
                let tipo = "token-normal".to_owned();
                let user_id = c.user_id;

                let token = generar_token(iss, sub, duracion_en_minutos, user_id, tipo);
                let resultado: RefreshResult = RefreshResult { token };

                HttpResponse::Ok().json(resultado)
            } else {
                HttpResponse::Unauthorized().body("")
            }
        }
        Err(_) => HttpResponse::Unauthorized().body(""),
    }
}

#[get("/privado")]
async fn privado() -> HttpResponse {
    HttpResponse::Ok().body("Privado")
}

#[get("/solo-director")]
#[protect("DIRECTOR")]
async fn solo_director() -> HttpResponse {
    HttpResponse::Ok().body("Información solo para directores")
}

#[get("/solo-supervisores")]
#[protect(any("DIRECTOR", "GERENTE"))]
async fn solo_supervisores() -> HttpResponse {
    HttpResponse::Ok().body("Información solo para supervisores")
}

fn id_igual_claim(path_param: web::Path<usize>, credenciales: Option<BearerAuth>) -> bool {
    let Some(credenciales) = credenciales else {
        return false;
    };
    let user_id = path_param.into_inner();
    let token = credenciales.token();
    let resultado = validar_token(token.to_owned());
    match resultado {
        Ok(claims) => claims.user_id == user_id,
        Err(_) => false,
    }
}

#[get("/inforamcion-personal/{user_id}")]
#[protect("LOG_IN", expr = "id_igual_claim(path_param, credenciales)")]
async fn info_personal(
    path_param: web::Path<usize>,
    credenciales: Option<BearerAuth>,
) -> HttpResponse {
    HttpResponse::Ok().body("Tu info personal")
}
// -------------------------------------------------------------------------------
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        let auth = HttpAuthentication::with_fn(validador);

        App::new()
            .app_data(BearerConfig::default().realm("jwt"))
            .service(
                web::scope("/admin")
                    .wrap(auth)
                    .service(privado)
                    .service(solo_director)
                    .service(solo_supervisores)
                    .service(info_personal),
            )
            .service(login)
            .service(refresh_token)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
