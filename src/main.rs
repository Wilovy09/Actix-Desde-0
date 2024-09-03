use chrono::{Duration, Utc};
use dotenv::dotenv;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Serialize, Deserialize, Debug)]
struct Claims {
    iss: String,
    sub: String,
    exp: usize,
    iat: usize,
    user_id: usize,
}

fn get_secret_key() -> String {
    dotenv().ok();
    let secret_key = env::var("SECRET_KEY").expect("SECRET_KEY must be set");
    secret_key
}

fn generar_token(iss: String, sub: String, duracion_en_minutos: i64, user_id: usize) -> String {
    let header = Header::new(Algorithm::HS512);
    let encoding_key = EncodingKey::from_secret(get_secret_key().as_bytes());

    let exp = (Utc::now() + Duration::minutes(duracion_en_minutos)).timestamp() as usize;
    let iat = Utc::now().timestamp() as usize;

    let my_claims = Claims {
        iss,
        sub,
        exp,
        iat,
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

fn main() {
    let iss = "Rust JWT".to_owned();
    let sub = "Prueba".to_owned();
    let duracion_en_minutos: i64 = 5;
    let user_id = 1;

    let token = generar_token(iss, sub, duracion_en_minutos, user_id);
    let resultado = validar_token(token);
    match resultado {
        Ok(claims) => println!("Los Claims son: {:?}", claims),
        Err(e) => println!("El token es invalido: {:?}", e),
    }
}
