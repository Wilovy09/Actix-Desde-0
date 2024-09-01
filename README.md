# Notas Actix

## Parametros con struct

```rust
use actix_web::{get, http::header, web, HttpResponse};
use serde::Deserialize;

#[derive(Deserialize)]
struct Parametros {
    id: u8,
    estado: String,
}

// Esto es con Path Params
#[get("/usuarios/{id}/{estado}")]
async fn usuario(parametros: web::Path<Parametros>) -> HttpResponse {
    HttpsResponse::Ok()
        .content_type(header::ContentType::json())
        .body(format!(r#"
        {{
            "id": {},
            "estado": "{}"
        }}
        "#, parametros.id, parametros.estado))
}

// Esto es con Query Params
#[get("/usuario")]
async fn usuario(parametros: web::Query<Parametros>) -> HttpResponse {
    HttpResponse::Ok()
        .content_type(header::ContentType::json())
        .body(format!(
            r#"{{
            "id": {},
            "estado": "{}"
        }}"#,
            parametros.id, parametros.estado
        ))
}
```

## Procesar JSONS

Para recibir jsons en post o asi

```rust
use actix_web::{post, web, HttpResponse};
use serde::Deserialize;

#[derive(Deserialize)]
struct SumaParams {
    a: u8,
    b: u8,
    c: u8,
}

#[post("/suma")]
// Actix se encarga de validar el tipo segun la struct (web::Json<STRUCT_NAME>)
async fn suma(parametros: web::Json<SumaParams>) -> HttpResponse {
    let resultado = parametros.a + parametros.b + parametros.c;
    HttpResponse::Ok().body(format!("Resultado es: {}", resultado))
}
```

## URL Encoded forms

```rust
use actix_web::{post, web, HttpResponse};
use serde::Deserialize;

#[derive(Deserialize)]
struct Persona {
    nombre: String,
    apellido: String,
    edad: u8,
}

#[post("/persona")]
async fn persona(parametros: web::Form<Persona>) -> HttpResponse {
    HttpResponse::Ok().body(format!(
        "Tu nombre es: {} {}, tu edad es: {}",
        parametros.nombre, parametros.apellido, parametros.edad
    ))
}
```

## Responder con JSONs

```rust
use actix_web::{get, web, Responder};
use serde::Serialize;

// Se pueden incluir ambas, Serialize y Deserialize en una misma struct
#[derive(Serialize)]
struct Autor {
    id: u8,
    nombre: String,
    apellido: String,
}

#[get("/autor")]
async fn autor() -> impl Responder {
    let autor: Autor = Autor {
        id: 1,
        nombre: "Wilovy".to_string(),
        apellido: "Rust".to_string(),
    };

    web::Json(autor)
}
```

Pero si queremos cambiar el `status code`, tenemos que retornar un `HttpResponse`

```rust
use actix_web::{get, web, HttpResponse};
use serde::Serialize;

#[derive(Serialize)]
struct Autor {
    id: u8,
    nombre: String,
    apellido: String,
}

#[get("/autor")]
async fn autor() -> HttpResponse {
    let autor: Autor = Autor {
        id: 1,
        nombre: "Wilovy".to_string(),
        apellido: "Rust".to_string(),
    };

    // Para mantenerlo sencillo usaremos Created (201)
    HttpResponse::Created().json(autor)
}
```

Pero..., los JSONs que estamos regresando son muy sencillos, mejor intentemos hacer que regrese el autor con un listado de libros.

```rust
use actix_web::{get, web, HttpResponse};
use serde::Serialize;


#[derive(Serialize)]
struct Libros {
    id: u8,
    titulo: String
}

#[derive(Serialize)]
struct Autor {
    id: u8,
    nombre: String,
    apellido: String,
    libros: Vec<Libros>
}

#[get("/autor")]
async fn autor() -> HttpResponse {
    let autor: Autor = Autor {
        id: 1,
        nombre: "Wilovy".to_string(),
        apellido: "Rust".to_string(),
        libros: vec![
            Libros {
                id: 1,
                titulo: "Rust desde 0".to_string(),
            },
            Libros {
                id: 1,
                titulo: "Actix desde 0".to_string(),
            },
        ],
    };

    // Para mantenerlo sencillo usaremos Created
    HttpResponse::Created().json(autor)
}
```

## Subir archivos

### Un solo archivo

Para lograr esto tenemos que agregar a nuestro formulario de html el atributo `enctype='multipart/form-data'` e instalar unas dependencias a nuestro proyecto

```html
<form action='subir-archivo' method='post' enctype='multipart/form-data'>
```

```sh
cargo add actix-multipart
cargo add futures-util
```

Ahora si nuestro código

```rust
use actix_multipart::Multipart;
use actix_web::{post, web, Error, HttpResponse};
use futures_util::TryStreamExt;
use std::io::Write;

#[post("/subir-archivo")]
async fn subir_archivo(mut payload: Multipart) -> Result<HttpResponse, Error> {
    while let Some(mut field) = payload.try_next().await? {
        // Verificamos si content_disposition tiene un valor válido
        let Some(content_disposition) = field.content_disposition() else { continue; };

        let file_name = content_disposition
            .get_filename()
            .expect("Falta nombre al archivo.");
        /* Esta es la ruta donde se guardara el archivo que nos manden en el API
         * Esto significa que buscara una carpeta `assets` en la raiz de nuestro proyecto
         * A la misma altura que src, target, Cargo.toml
        */
        let file_path = format!("./assets/{file_name}");

        let mut archivo = web::block(|| std::fs::File::create(file_path)).await??;

        while let Some(chunk) = field.try_next().await? {
            archivo = web::block(move || archivo.write_all(&chunk).map(|_| archivo)).await??;
        }
    }
    Ok(HttpResponse::Ok().body("Archivo subido correctamente"))
}
```

Para probar nuestra API en un HttpClient (Insomnia) tenemos que irnos a `Body`>`Multipart form`> y en value seleccionar `file`

Un error que tiene esto, es que si se vuelve a enviar un archivo con el mismo nombre, se sobreescribe el archivo anterior.

### Subir mayor información, no solo un archivo

```rust
use actix_multipart::form::{tempfile::TempFile, text::Text, MultipartForm};
use actix_web::{post, web, Error, HttpResponse};

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(subir_archivos);
}

#[derive(Debug, MultipartForm)]
pub struct FormularioConArchivos {
    pub nombre: Text<String>,
    pub apellido: Text<String>,
    pub archivo: TempFile,
    // pub archivo2: TempFile,
}

#[post("/subir-archivos")]
async fn subir_archivos(
    MultipartForm(form): MultipartForm<FormularioConArchivos>,
) -> Result<HttpResponse, Error> {
    println!(
        "Nombre: {}, Apellido: {}",
        form.nombre.as_str(),
        form.apellido.as_str()
    );

    // Si fuera una lista de archivos seria hacer un loop
    let file_name = form.archivo.file_name.unwrap();
    let file_path = format!("./assets/{file_name}");
    form.archivo.file.persist(file_path).unwrap();

    Ok(HttpResponse::Ok().body("Archivo subidos correctamente"))
}
```

Y en nuestro HttpClient hariamos algo asi:

![Insomnia]("./public/multipart_files.png")

El "problema" que tiene esto es que `MultipartForm` tiene un limite de subida, por defecto son `50mb` en total, si se manda más de `50mb` totales te dara un error donde se dice que se excedio el limite de memoria (error 400).

### Aumentar el espacio en memoria

```rust
// Importamos `MultipartFormConfig` de form
use actix_multipart::form::MultipartFormConfig;
use actix_web::{App, HttpServer};
mod routes;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        // Definos una constante para definir nuestros mb
        const MB: usize = 1024 /* 1024 es un kb */ * 1024 /* 1kb x 1024 = 1mb */ * 100 /* 1mb x 100 = 100mb */;
        // Definimos una variable para nuestra config
        let multipartform_config = MultipartFormConfig::default()
            // El tamaño de estos metodos es en `bytes`
            .total_limit(MB)
            .memory_limit(MB);
        App::new()
            .app_data(multipartform_config)
            //...code...
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

