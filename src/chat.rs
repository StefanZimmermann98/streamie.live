use rocket::{State, Shutdown};
use rocket::form::Form;
use rocket::response::stream::{EventStream, Event};
use rocket::serde::{Serialize, Deserialize};
use rocket::tokio::sync::broadcast::{Sender, error::RecvError};
use rocket::tokio::select;
use rocket::http::{Cookie, CookieJar};

use crate::security::{SecurityRole, validate_token};
// FormGuard und Basis-Struct für eine neue Nachricht
#[derive(Debug, Clone, FromForm, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, UriDisplayQuery))]
#[serde(crate = "rocket::serde")]
pub struct Message {
    #[field(validate = len(..30))]
    pub room: String,
    #[field(validate = len(..30))]
    pub message: String,
}

// Struct für eine ChatMessage die an alle gebroadcastet werden soll
#[derive(Debug, Clone, FromForm, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct ChatMessage {
    pub room: String,
    pub username: String,
    pub message: String,
    pub chat_type: String // Type ist hier die Rolle zur farblichen Markierung bestimmter User
}

// Abboniere einen Channel
#[get("/chat")]
pub async fn retrieve_chat(queue: &State<Sender<ChatMessage>>, mut end: Shutdown, cookies: &CookieJar<'_>) -> EventStream![] {
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
            let mut rx = queue.subscribe();
            // Für die Server-Send-Events wurde die Rocket.rs Klasse EventStream genutzt
            EventStream! {
                loop {
                    let msg = select! {
                        msg = rx.recv() => match msg {
                            Ok(msg) => msg,
                            Err(RecvError::Closed) => break,
                            Err(RecvError::Lagged(_)) => continue,
                        },
                        _ = &mut end => break,
                    };

                    yield Event::json(&msg);
                }
            }
        },
        None => {
            // Leider keine bessere Lösung gefunden
            panic!("Unauthorized Chat");
        }
    }
    
}

// End-Knoten für das Absetzen einer neuen Nachricht in einem Channel
#[post("/message", data = "<form>")]
pub fn retrieve_message(form: Form<Message>, queue: &State<Sender<ChatMessage>>, cookies: &CookieJar<'_>) {
    
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
            let form = form.into_inner();
            let chat_message = ChatMessage {
                room: form.room,
                username: t.username,
                message: form.message,
                chat_type: if t.role == SecurityRole::ADMIN {
                    "admin".to_string()
                } else if t.role == SecurityRole::MODERATOR {
                    "mod".to_string()
                } else {
                    "user".to_string()
                }
            };
            let _res = queue.send(chat_message);
        },
        None => {
            return;
        }
        
    }

}