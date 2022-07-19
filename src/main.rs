#[macro_use] extern crate rocket;
extern crate core;

//#[macro_use] extern crate rocket_contrib;
use rocket::http::{Header, ContentType};
use rocket_dyn_templates::{Template};
use rocket::http::{Cookie, CookieJar};
use rocket::fs::{relative, FileServer, Options};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use mongodb::bson::doc;
use mongodb::bson::oid::ObjectId;
use mongodb::Client;
use mongodb::options::ClientOptions;
use serde::Serialize;
use serde::Deserialize;

/**
 * Imports for Server Send Events
 */
use rocket::tokio::sync::broadcast::{channel};
mod chat;
use crate::chat::retrieve_chat;
use crate::chat::retrieve_message;
use crate::chat::ChatMessage;

/**
 * Imports for all Session-related stuff
 */
use crate::sessions::SessionStream;
use crate::sessions::list_sessions;
use crate::sessions::single_session;

use crate::administration::show_overview;
use crate::administration::add_session;
use crate::administration::ask_session_detail;
use crate::administration::ask_session_detail_update;
use crate::administration::admin_update_session;
use crate::administration::ask_session_detail_delete;
use crate::administration::delete_session;

/**
 * Imports for all Security-related stuff
 */
use crate::security::login;
use crate::security::login_proceed;
use crate::security::logout;

/**
 * Imports for all Usermanagement-related stuff
 */

use crate::usermanagement::{
    list_all_user,
    create_new_user,
    delete_existing_user
};

mod security;
mod database;
mod sessions;
mod administration;
mod usermanagement;

// Index Page
#[get("/")]
fn index(cookies: &CookieJar<'_>) -> Template {

    let token: Option<Cookie> = cookies.get_private("streamie.live");
    let token_value = match token {
        Some(jwt) => jwt,
        None => Cookie::new("streamie.live", "None")
    };

    let fullname: Option<Cookie> = cookies.get_private("fullname");
    let fullname_value = match fullname {
        Some(fullname) => fullname,
        None => Cookie::new("fullname", "Unknown User")
    };

    let mut context: HashMap<&str, &str> = HashMap::new();
    context.insert("jwt", token_value.value());
    context.insert("fullname", fullname_value.value());

    return Template::render("index", &context);
}

// Eigene 500er Renderings, werden vom Catcher in rocket.rs gefangen 
#[catch(500)]
fn internal_error() -> Template {
    let mut context: HashMap<&str, &str> = HashMap::new();
    return Template::render("internal_error", &context);
}

// Eigene 404er Renderings, werden vom Catcher in rocket.rs gefangen 
#[catch(404)]
fn not_found() -> Template {
    let mut context: HashMap<&str, &str> = HashMap::new();
    return Template::render("not_found", &context);
}

#[launch]
fn rocket() -> _ {
    
    let options = Options::Index | Options::DotFiles;

    rocket::build()
    .manage(channel::<ChatMessage>(1024).0)
    .mount("/", routes![
        index,
        logout,
        login,
        login_proceed,
        list_sessions,
        single_session,
        retrieve_message,
        retrieve_chat,
        show_overview,
        add_session,
        ask_session_detail,
        ask_session_detail_update,
        admin_update_session,
        ask_session_detail_delete,
        delete_session,
        list_all_user,
        create_new_user,
        delete_existing_user
    ])
    .mount("/", FileServer::new("./static", options))
    .register("/", catchers![internal_error, not_found])
    .attach(Template::fairing())
}