use std::env;
use std::process;
use std::ffi::OsString;
use std::error::Error;
use std::io::Write;
use encoding_rs::*;
use serde::{Serialize,Deserialize,Deserializer};
use std::collections::BTreeMap;
use std::result;
use std::fs::File;

fn main() {
    if let Err(err) = run() {
        println!("{}", err);
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {

    let file_path = get_nth_arg(1)?;
    let mut rdr = csv::ReaderBuilder::new()
            .from_path(file_path)?;
    let mut wtr0 = csv::Writer::from_path("./datos_procesados_r/delitos_dicc.csv")?;
    let mut salida = File::create("./datos_procesados_r/delitos.json")?;

    let headers = rdr.byte_headers()?.clone();
    let headers = recoder(&headers)?;

    let mut tipos: BTreeMap<String, String> = BTreeMap::new();
    let mut subtipos: BTreeMap<String, String> = BTreeMap::new();
    let mut modalidades: BTreeMap<String, String> = BTreeMap::new();
    let mut diccionario: BTreeMap<String,Categoria> = BTreeMap::new();

    let mut datos: BTreeMap<String, BTreeMap<String, BTreeMap<String,u32>>> = BTreeMap::new();

    let mut tip_cve_max: u32 = 1;
    let mut stp_cve_max: u32 = 1;
    let mut mod_cve_max: u32 = 1;
    for result in rdr.byte_records() {
        match result {
            Ok(record) => {

                let encoded_record = recoder(&record)?;

                let mut new_record = match encoded_record.deserialize::<Delito>(Some(&headers)) {
                    Ok(new_record) => new_record,
                    Err(err) => {
                        println!("{:?}",encoded_record);
                        return Err(Box::new(err));
                    }
                };

                new_record.clave_ent = format!("{:0>2}",new_record.clave_ent);
                new_record.clave_mun = format!("{:0>5}",new_record.clave_mun);

                match tipos.get(&new_record.tipo_delito) {
                    Some(cve) => {
                        new_record.tipo_cve = cve.clone();
                    },
                    None => {
                        let tip_cve = format!("T{:0>2}",tip_cve_max.to_string());
                        new_record.tipo_cve = tip_cve.clone();
                        tipos.insert(new_record.tipo_delito.clone(),tip_cve);
                        tip_cve_max += 1;
                    }
                }

                match subtipos.get(&new_record.subtipo_delito) {
                    Some(cve) => {
                        new_record.subtipo_cve = cve.clone();
                    },
                    None => {
                        let stp_cve = format!("S{:0>2}",stp_cve_max.to_string());
                        new_record.subtipo_cve = stp_cve.clone();
                        subtipos.insert(new_record.subtipo_delito.clone(),stp_cve);
                        stp_cve_max += 1;
                    }
                }

                match modalidades.get(&new_record.modalidad) {
                    Some(cve) => {
                        new_record.modalidad_cve = cve.clone();
                    },
                    None => {
                        let mod_cve = format!("M{:0>2}",mod_cve_max.to_string());
                        new_record.modalidad_cve = mod_cve.clone();
                        modalidades.insert(new_record.modalidad.clone(),mod_cve);
                        mod_cve_max += 1;
                    }
                }

                new_record.cve = format!("{}{}{}",
                                        new_record.tipo_cve,
                                        new_record.subtipo_cve,
                                        new_record.modalidad_cve);

                let municipio = &new_record.clave_mun;

                let mapadel = datos.entry(new_record.cve.clone()).or_insert(BTreeMap::new());

                diccionario.entry(new_record.cve.clone())
                    .or_insert(Categoria::from_delito(&new_record));

                for (index,val) in new_record.incidencias().iter().enumerate() {
                    if *val != 0 {
                        let fecha = format!("{}-{:0>2}",new_record.year,index + 1);
                        let fechamap = mapadel.entry(fecha).or_insert(BTreeMap::new());
                        fechamap.insert(municipio.clone(),*val);
                    }
                }
            },
            Err(_) => continue
        }
    }

    for (_, val) in diccionario.iter() {
        wtr0.serialize(val)?;
    }
    wtr0.flush()?;

    let j = serde_json::to_string(&datos)?;
    write!(salida, "{}", j)?;

    Ok(())
}

fn recoder(record: &csv::ByteRecord) -> Result<csv::StringRecord, Box<dyn Error>> {
    let new_record = record.iter().map(|field| {
        let (cow, _, _) = WINDOWS_1252.decode(field);
        cow
    }).collect();

    Ok(new_record)
}

fn get_nth_arg(n: usize) -> Result<OsString, Box<dyn Error>> {
    match env::args_os().nth(n) {
        None => Err(From::from("no se pudo leer el argumento")),
        Some(file_path) => Ok(file_path)
    }
}

#[derive(Debug, Serialize)]
struct Categoria {
    #[serde(rename = "Tipo de delito")]
    tipo_delito: String,
    #[serde(rename = "Subtipo de delito")]
    subtipo_delito: String,
    #[serde(rename = "Modalidad")]
    modalidad: String,
    #[serde(rename = "CVETPO")]
    tipo_cve: String,
    #[serde(rename = "CVESUB")]
    subtipo_cve: String,
    #[serde(rename = "CVEMOD")]
    modalidad_cve: String,
    #[serde(rename = "CVE")]
    cve: String
}

impl Categoria {
    fn from_delito(delito: &Delito) -> Categoria {
        Categoria {
            tipo_delito: delito.tipo_delito.clone(),
            subtipo_delito: delito.subtipo_delito.clone(),
            modalidad: delito.modalidad.clone(),
            tipo_cve: delito.tipo_cve.clone(),
            subtipo_cve: delito.subtipo_cve.clone(),
            modalidad_cve: delito.modalidad_cve.clone(),
            cve: delito.cve.clone()
        }
    }
}

#[derive(Debug, Deserialize)]
struct Delito{
    #[serde(rename = "Año")]
    year: u32,
    #[serde(rename = "Clave_Ent")]
    clave_ent: String,
    #[serde(rename = "Entidad")]
    entidad: String,
    #[serde(rename = "Cve. Municipio")]
    clave_mun: String,
    #[serde(rename = "Municipio")]
    municipio: String,
    #[serde(rename = "Bien jurídico afectado")]
    bien_afectado: String,
    #[serde(rename = "Tipo de delito")]
    tipo_delito: String,
    #[serde(rename = "Subtipo de delito")]
    subtipo_delito: String,
    #[serde(rename = "Modalidad")]
    modalidad: String,
    #[serde(rename = "Enero")]
    #[serde(deserialize_with = "only_positives")]
    enero: u32,
    #[serde(rename = "Febrero")]
    #[serde(deserialize_with = "only_positives")]
    febrero: u32,
    #[serde(rename = "Marzo")]
    #[serde(deserialize_with = "only_positives")]
    marzo: u32,
    #[serde(rename = "Abril")]
    #[serde(deserialize_with = "only_positives")]
    abril: u32,
    #[serde(rename = "Mayo")]
    #[serde(deserialize_with = "only_positives")]
    mayo: u32,
    #[serde(rename = "Junio")]
    #[serde(deserialize_with = "only_positives")]
    junio: u32,
    #[serde(rename = "Julio")]
    #[serde(deserialize_with = "only_positives")]
    julio: u32,
    #[serde(rename = "Agosto")]
    #[serde(deserialize_with = "only_positives")]
    agosto: u32,
    #[serde(rename = "Septiembre")]
    #[serde(deserialize_with = "only_positives")]
    septiembre: u32,
    #[serde(rename = "Octubre")]
    #[serde(deserialize_with = "only_positives")]
    octubre: u32,
    #[serde(rename = "Noviembre")]
    #[serde(deserialize_with = "only_positives")]
    noviembre: u32,
    #[serde(rename = "Diciembre")]
    #[serde(deserialize_with = "only_positives")]
    diciembre: u32,
    #[serde(default)]
    tipo_cve: String,
    #[serde(default)]
    subtipo_cve: String,
    #[serde(default)]
    modalidad_cve: String,
    #[serde(default)]
    cve: String
}

impl Delito {
    fn incidencias(&self) -> [u32;12] {
            [self.enero,
            self.febrero,
            self.marzo,
            self.abril,
            self.mayo,
            self.junio,
            self.julio,
            self.agosto,
            self.septiembre,
            self.octubre,
            self.noviembre,
            self.diciembre]
    }
}

pub fn only_positives<'de, D>(de: D) -> result::Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    match u32::deserialize(de) {
        Ok(num) => Ok(num),
        _ => Ok(0)
    }
}

