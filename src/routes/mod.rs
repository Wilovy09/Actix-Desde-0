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
