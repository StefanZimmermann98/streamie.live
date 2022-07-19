use std::collections::HashMap;
use serde::Serialize;
use chrono::{DateTime, NaiveDateTime, Utc};
use rocket::form::Form;
use rocket::fs::FileServer;
use rocket::http::{Cookie, CookieJar};
use rocket_dyn_templates::{Template, context};
use crate::database::{add_new_session, get_client, get_session_by_name, get_standard_database, remove_session_by_name, update_session};
use crate::ObjectId;
use crate::sessions::{Session, SessionStream, StreamType, User};


use crate::security::validate_token;
use crate::security::{SecurityToken, SecurityRole};

use crate::sessions::FORMAT_STR;



#[derive(Serialize)]
struct AdminContext<'a> {
    jwt: &'a str,
    fullname: &'a str,
    token: SecurityToken
}

fn get_token_value(token: Option<Cookie>)->Cookie{
    let token_value = match token {
        Some(jwt) => jwt,
        None => Cookie::new("streamie.live", "None")
    };
    token_value
}

fn get_fullname(fullname: Option<Cookie>) ->Cookie{
    let fullname_value = match fullname {
        Some(fullname) => fullname,
        None => Cookie::new("fullname", "Unknown User")
    };
    fullname_value
}

//Anzeigen der verschiedenen Buttons mittels des Admin-Templates
#[get("/admin")]
pub fn show_overview(cookies: &CookieJar<'_>) -> Template {

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

            if t.role != SecurityRole::ADMIN {
                return Template::render("unauthorized", context!{});
            }

            let fullname: Option<Cookie> = cookies.get_private("fullname");
            let fullname_value = get_fullname(fullname);

            return Template::render("sessions/admin", AdminContext {
                jwt: token_value.value(),
                fullname: fullname_value.value(),
                token: t
            });
        },
        None => {
            return Template::render("unauthorized",  context!{});
        }
    }

}

//Struct mit allen Inputs für eine Session als Strings, die Inputs müssen eine minimal Länge von 1 haben
#[derive(FromForm, Debug)]
pub struct NewSession<'r> {
    #[field(validate = len(1..))]
    start: &'r str, //Umformatierung in Datetime
    #[field(validate = len(1..))]
    end: &'r str,
    #[field(validate = len(1..))]
    name: &'r str,
    #[field(validate = len(1..))]
    description: &'r str,
    #[field(validate = len(1..))]
    link: &'r str,
    #[field(validate = len(1..))]
    channel: &'r str,
    #[field(validate = len(1..))]
    plattform: &'r str,

}

//Anzeigen des Creation-Templates für Sessions
#[get("/session/list/create")]
pub async fn ask_session_detail(cookies: &CookieJar<'_>) -> Template
{
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

            if t.role != SecurityRole::ADMIN {
                return Template::render("unauthorized", context!{});
            }

            let fullname: Option<Cookie> = cookies.get_private("fullname");
            let fullname_value = get_fullname(fullname);

            return Template::render("admin/create_session", AdminContext {
                jwt: token_value.value(),
                fullname: fullname_value.value(),
                token: t
            });

        },
        None => {
            return Template::render("unauthorized", context!{});
        }
    }

}

//Methode zum Erstellen von Sessions
#[post("/admin/session/add",  data = "<newSession>")]
pub async  fn add_session(newSession:  Form<NewSession<'_>>, cookies: &CookieJar<'_>)-> Template{
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

            if t.role != SecurityRole::ADMIN {
                return  Template::render("unauthorized", context!{});
            }
            //Umformatierung der Daten aus Strings in die richtigen Formate , wie bsp. Datetimes
            let database = get_standard_database().await;
            let startS = DateTime::<Utc>::from_utc(NaiveDateTime::parse_from_str(
                newSession.start, FORMAT_STR).expect("failed to parse startDateTime"), Utc);
            let endS = DateTime::<Utc>::from_utc(NaiveDateTime::parse_from_str(
                newSession.end, FORMAT_STR).expect("failed to parse startDateTime"), Utc);
            let mut stream_type_session= StreamType::Twitch;
            //Zuweisung des Stream_types-Enums
            if newSession.plattform.to_string().eq("Youtube") {
                stream_type_session = StreamType::Youtube;
            }else if newSession.plattform.to_string().eq("None") {
                stream_type_session = StreamType::None;
            }else {
                stream_type_session = StreamType::Twitch;
            }
            //Erstellung einer neuen Session aus den erhaltenen und Umformatierten Daten
            let sessionD:Session = Session{
                id: ObjectId::new(),
                start: startS,
                end:  endS,
                name: newSession.name.to_string(),
                description: newSession.description.to_string(),
                stream:SessionStream{
                    link: newSession.link.to_string(),
                    channel: newSession.channel.to_string(),
                    stream_type: stream_type_session
                },
            };
            //Eingabe der Session in die DB und dortige Erstellung
            add_new_session(&database, &sessionD).await;
            return show_overview(cookies)
        },
        None => {
            return  Template::render("unauthorized", context!{});
        }
    }
}


//Anzeigen des Update-Templates zum Befüllen der Update Werte
#[get("/session/list/update")]
pub async fn ask_session_detail_update(cookies: &CookieJar<'_>) ->Template
{

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

                if t.role != SecurityRole::ADMIN {
                    return  Template::render("unauthorized", context!{});
                }

                let fullname: Option<Cookie> = cookies.get_private("fullname");
                let fullname_value = get_fullname(fullname);

                return Template::render("admin/update_session", AdminContext {
                    jwt: token_value.value(),
                    fullname: fullname_value.value(),

                    token: t

                });
        },
        None => {
                return  Template::render("unauthorized", context!{});
        }
    }

}

//Struct mit den Werten die Upgedaten werden sollen, können die Länge 0 sein => Felder müssen nicht gesetzt sein, außer old_name
#[derive(FromForm)]
pub struct UpSession<'r> {
    #[field(validate = len(0..))]
    start: &'r str, //Umformatierung in Datetime
    #[field(validate = len(0..))]
    end: &'r str,
    #[field(validate = len(0..))]
    name: &'r str,
    #[field(validate = len(0..))]
    description: &'r str,
    #[field(validate = len(0..))]
    link: &'r str,
    #[field(validate = len(0..))]
    channel: &'r str,
    #[field(validate = len(0..))]
    plattform: &'r str,
    #[field(validate = len(1..))]
    old_name: &'r str,
}

//Methode zum Updaten der Session mit einem Input aus Daten die in dem obigen Struct übergeben werden
#[put("/admin/session/update",  data = "<updated_session>")]
pub async  fn admin_update_session(updated_session:  Form<UpSession<'_>>, cookies: &CookieJar<'_>)-> () {

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

                if t.role != SecurityRole::ADMIN {
                    return;
                }

                let database = get_standard_database().await;
                let mut session: Session = get_session_by_name(&database, updated_session.old_name.to_string()).await;

                //alle neuen Werte werden in einer Hash Map gespeichert
                let mut map :HashMap<&str, &str> = HashMap::new();
                map.insert("name", updated_session.name);
                map.insert("description", updated_session.description);
                map.insert("start", updated_session.start);
                map.insert("end", updated_session.end);
                map.insert("link", updated_session.link);
                map.insert("channel", updated_session.channel);
                map.insert("plattform", updated_session.plattform);

                //iteration über die hash map  Überprüfung ob der neue Wert existiert
                for(key, val) in map.iter(){
                    if !val.to_string().is_empty(){
                        //wenn der Wert nicht null ist wird er neu gesetzt, sonst bleibt der alte Wert bestand
                        match key {
                            &"name" => session.name = val.to_string(),
                            &"description"=> session.description = val.to_string(),
                            &"start"=> session.start = DateTime::<Utc>::from_utc(NaiveDateTime::parse_from_str(
                                val, FORMAT_STR).expect("failed to parse startDateTime"), Utc),
                            &"end" => session.end =  DateTime::<Utc>::from_utc(NaiveDateTime::parse_from_str(
                                val, FORMAT_STR).expect("failed to parse startDateTime"), Utc),
                            &"channel"=> session.stream.channel = val.to_string(),
                            &"link" => session.stream.link = val.to_string(),
                            &"plattform"=>if updated_session.plattform.to_string().eq("Youtube") {
                                                session.stream.stream_type = StreamType::Youtube;
                                            }else if updated_session.plattform.to_string().eq("None") {
                                                session.stream.stream_type = StreamType::None;
                                            }else {
                                                session.stream.stream_type = StreamType::Twitch;
                                            }
                            _ => {}
                        }
                    }
                }
            //session wird in der Datenbank geupdated
                update_session(&database, &session).await;
        },
        None => {

        }
    }
}

//Anzeigen des Delete-Templates
#[get("/session/list/delete")]
pub async fn ask_session_detail_delete(cookies: &CookieJar<'_>) ->Template
{
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

                if t.role != SecurityRole::ADMIN {
                    return  Template::render("unauthorized", context!{});
                }

                let fullname: Option<Cookie> = cookies.get_private("fullname");
                let fullname_value = get_fullname(fullname);

                return Template::render("admin/delete_session", AdminContext {
                    jwt: token_value.value(),
                    fullname: fullname_value.value(),
                    token: t

                });
        },
        None => {
                return  Template::render("unauthorized", context!{});
        }
    }

}

//Struct mit einem String der mindestens 1 groß sein muss, wird benötigt zum löschen
#[derive(FromForm)]
pub struct DelSession<'r> {
    #[field(validate = len(1..))]
    name: &'r str,
}

//Löschen Einer Session aktuell über den Namen der Session
#[delete("/session/delete/<stream_name>" )]
pub async fn delete_session( stream_name: &str ,cookies: &CookieJar<'_>) -> () {
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

            if t.role != SecurityRole::ADMIN {
                return;
            }

            //Datenbank wird geholt und Session wird aus dieser gelöscht
            let database = get_standard_database().await;
            remove_session_by_name(&database, stream_name.to_string()).await;
        },
        None => {
            return;
        }
    }
}

#[launch]
fn rocket() -> _ {

    rocket::build()
        .mount("/", routes![
        show_overview,
        add_session,
        ask_session_detail,
        ask_session_detail_update,
        admin_update_session,
        ask_session_detail_delete,
        delete_session,

    ])
        .attach(Template::fairing())
}

#[cfg(test)]
mod tests {
    use cookie::Expiration::Session;
    use futures::task::Spawn;
    use mongodb::Database;
    use super::rocket;
    use super::*;
    use rocket::http::Status;
    //use rocket::local::blocking::Client;
    use rocket::local::asynchronous::Client;
    use rocket::Response;
    use rocket::response::Body;
    use crate::{ContentType, SessionStream};
    use crate::administration::NewSession;
    use crate::database::{get_database_by_name, TEST_DATABASE_NAME};
    use crate::sessions::StreamType;

    #[tokio::test]
    async fn test_admin_overview(){
        let client = Client::tracked(rocket()).await.expect("valid rocket instance");
        let mut response = client.get(uri!(super::show_overview)).dispatch();
        assert_eq!(response.await.status(), Status::Ok);
    }


    #[tokio::test]
    async fn test_admin_ask_session_detail(){
        let n1 = super::NewSession{
            start: "09.07.2022 07:48:15",
            end: "10.07.2022 07:48:15",
            name: "Test",
            description: "ein Test zum Streamen",
            link: "https://www.twitch.tv/primeleague",
            channel: "PrimeLeague",
            plattform: "Twitch"
        };
        let client = Client::tracked(rocket()).await.expect("valid rocket instance");
        let mut response = client.get(uri!(super::ask_session_detail)).dispatch().await;
        assert_eq!(response.status(), Status::Ok);
    }



    #[tokio::test]
    async fn test_ask_session_detail_delete(){
        let client = Client::tracked(rocket()).await.expect("Error with Client at Session_detail_Delete");
        let mut response = client.get(uri!(super::ask_session_detail_delete)).dispatch().await;
        assert_eq!(response.status(), Status::Ok);
    }

    #[tokio::test]
    async fn test_admin_delete_session() {

        let sessionD = super::Session{
            id: ObjectId::new(),
            start:  DateTime::<Utc>::from_utc(NaiveDateTime::parse_from_str(
                "09.07.2022 07:48:15", FORMAT_STR).expect("failed to parse startDateTime"), Utc),
            end:  DateTime::<Utc>::from_utc(NaiveDateTime::parse_from_str(
                "10.07.2022 07:48:15", FORMAT_STR).expect("failed to parse startDateTime"), Utc),
            name: "Test".to_string(),
            description: "ein Test zum Streamen".to_string(),
            stream:SessionStream{
                link: "https://www.twitch.tv/primeleague".to_string(),
                channel: "PrimeLeague".to_string(),
                stream_type: StreamType::Twitch
            },
        };
        let database = get_standard_database().await;
        add_new_session(&database, &sessionD).await;
        let del1 = "Test";
        let client = Client::tracked(rocket()).await.expect("valid rocket instance");

        let mut response = client.delete(uri!(super::delete_session(del1))).dispatch().await;
        assert_eq!(response.status(), Status::Ok);
    }

    #[tokio::test]
    async fn test_ask_session_detail_update(){
        let client = Client::tracked(rocket()).await.expect("Error with Client at Session_detail_Delete");
        let mut response = client.get(uri!(super::ask_session_detail_update)).dispatch().await;
        assert_eq!(response.status(), Status::Ok);
    }

    }
