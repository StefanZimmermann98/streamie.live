use chrono::{DateTime, Utc};
use mongodb::bson::oid::ObjectId;
use serde::Serialize;
use serde::Deserialize;
use rocket_dyn_templates::{Template, context};
use rocket::http::{Cookie, CookieJar};
use crate::security::{SecurityToken, validate_token};
use crate::database::{get_client, get_standard_database};
use crate::database::get_all_sessions;
use crate::database::get_session_by_id;

// Aktuell nur Twitch und Youtube implementiert
#[derive(Debug, Serialize, Deserialize)]
pub enum StreamType {
    Twitch,
    Youtube,
    None
}

// Basis-Daten für einen Stream
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionStream {
    pub link: String,
    pub channel: String,
    pub stream_type: StreamType
}

// Dieser Session-struct bildet das MongoDB deserialisierte Objekt ab
#[derive(Debug, Serialize, Deserialize)]
pub struct Session {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub name: String,
    pub description: String,
    pub stream: SessionStream
}

// Aufgrund des Problems, dass die MongoDB ObjectId von Tera nicht sauber verarbeitet werden kann
// musste hier ein eigenes TeraSession-Struct erzeugt werden 
#[derive(Debug, Serialize, Deserialize)]
pub struct TeraSession {
    #[serde(rename = "_id")]
    pub id: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub name: String,
    pub description: String,
    pub stream: SessionStream
}

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub username: String,
    pub hash: String,
    pub salt: String,
    pub role: String,
    pub fullname: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TeraUser {
    #[serde(rename = "_id")]
    pub id: String,
    pub username: String,
    pub hash: String,
    pub salt: String,
    pub role: String,
    pub fullname: String,
}

// Basis Zeit Formatierung (Europa)
pub const FORMAT_STR: &str = "%d.%m.%Y %H:%M:%S";

// Übersichts-Liste aller Sessions
#[get("/sessions")]
pub async fn list_sessions(cookies: &CookieJar<'_>) -> Template {
    
    // streamie.live ist der Standardcookie für den Auth-Token
    let token: Option<Cookie> = cookies.get_private("streamie.live");
    let token_value = match token {
        Some(jwt) => jwt,
        None => Cookie::new("streamie.live", "None")
    };

    let valuated_token = validate_token(token_value.value().to_string());

    // Falls Token abgelaufen oder ungültig -> render unauthorized template
    match valuated_token {
        Some(t) => {
            let fullname: Option<Cookie> = cookies.get_private("fullname");
            let fullname_value = match fullname {
                Some(fullname) => fullname,
                None => Cookie::new("fullname", "Unknown User")
            };


            #[derive(Serialize)]
            struct EventsContext<'a> {
                jwt: &'a str,
                fullname: &'a str,
                sessions: Vec<TeraSession>,
                token: SecurityToken
            }

            let database = get_standard_database().await;
            let streams: Vec<Session> = get_all_sessions(&database).await;

            // Aufgrund der MongoDB ObjectId müssen alle Sessions in eine eigene Tera-Session überführt werden
            let mut tera_streams: Vec<TeraSession> = Vec::new();
            for stream in streams {
                tera_streams.push(TeraSession {
                    id: stream.id.to_hex(),
                    start: stream.start,
                    end: stream.end,
                    stream: stream.stream,
                    description: stream.description,
                    name: stream.name
                });
            }

            return Template::render("sessions/events", EventsContext {
                jwt: token_value.value(),
                fullname: fullname_value.value(),
                sessions: tera_streams,
                token: t
            });
        },
        None => {
            return  Template::render("unauthorized", context!{});
        }
    }

    
}

// Anzeige einer einzelnen Session
// id ist hierbei eine MongoDB ObjectId als String
#[get("/session/<id>")]
pub async fn single_session(id: String, cookies: &CookieJar<'_>) -> Template {
    
    // streamie.live ist der Standard-Cookie für den Auth Token
    let token: Option<Cookie> = cookies.get_private("streamie.live");
    let token_value = match token {
        Some(jwt) => jwt,
        None => Cookie::new("streamie.live", "None")
    };

    let valuated_token = validate_token(token_value.value().to_string());

    // Wenn token abgelaufen oder ungültig => Zeige unauthorized
    match valuated_token {
        Some(t) => {

            let current_session: Session;

            // Suche nach der Session, auf welche navigiert wurde
            // Hier fliegt ein panic wenn nicht gefunden -> könnte verschönert werden
            let database = get_standard_database().await;
            current_session = get_session_by_id(&database, &ObjectId::parse_str(&id).unwrap()).await;

            // Überführe die Session, falls gefunden in eine Tera Session
            let current_tera_session = TeraSession {
                id: current_session.id.to_hex(),
                start: current_session.start,
                end: current_session.end,
                stream: current_session.stream,
                description: current_session.description,
                name: current_session.name
            };

            #[derive(Serialize)]
            struct SessionContext<'a> {
                jwt: &'a str,
                fullname: &'a str,
                session: TeraSession,
                token: SecurityToken
            }

            #[derive(Serialize)]
            struct ErrorContext<'a> {
                jwt: &'a str,
                fullname: &'a str
            }

            let fullname: Option<Cookie> = cookies.get_private("fullname");
            let fullname_value = match fullname {
                Some(fullname) => fullname,
                None => Cookie::new("fullname", "Unknown User")
            };

            return Template::render("sessions/session", SessionContext {
                jwt: token_value.value(),
                fullname: fullname_value.value(),
                session: current_tera_session,
                token: t
            });
        },
        None => {
            return  Template::render("unauthorized", context!{});
        }
    }

    

}

#[launch]
fn rocket() -> _ {

    rocket::build()
        .mount("/", routes![
            single_session,
            list_sessions,
    ]).attach(Template::fairing())
}

#[cfg(test)]
mod tests {

    use super::rocket;
    use rocket::http::Status;
    use rocket::local::asynchronous::Client;

    #[tokio::test]
    async fn test_session_list() {
        let client = Client::tracked(rocket()).await.expect("valid rocket instance");
        let mut response = client.get(uri!(super::list_sessions)).dispatch();
        assert_eq!(response.await.status(), Status::Ok);
    }

    #[tokio::test]
    async fn test_single_session() {
        let client = Client::tracked(rocket()).await.expect("valid rocket instance");
        let mut response = client.get(uri!(super::single_session("62a05c8631a6964f64d829ac'".to_string()))).dispatch();
        assert_eq!(response.await.status(), Status::Ok);
    }
}