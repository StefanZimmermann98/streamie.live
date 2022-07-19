use rocket_dyn_templates::{Template, context};
use rocket::http::{Cookie, CookieJar};

use serde::Serialize;
use rocket::serde::{json::Json};
use rocket::form::Form;

use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;

use mongodb::bson::oid::ObjectId;

use crate::security::{validate_token, SecurityRole, SecurityToken};
use crate::sessions::{User, TeraUser};
use crate::database::{get_client, get_all_users, create_hash, add_new_user, remove_user_by_id, get_standard_database};

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
pub struct UserResult { 
    pub status: u8
}

#[get("/usermanagement")]
pub async fn list_all_user(cookies: &CookieJar<'_>) -> Template {
    
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
            let fullname_value = match fullname {
                Some(fullname) => fullname,
                None => Cookie::new("fullname", "Unknown User")
            };
            let database = get_standard_database().await;
            let user_list: Vec<User> = get_all_users(&database).await;
            let mut user_list_tera: Vec<TeraUser> = Vec::new();

            for user in user_list {
                user_list_tera.push(TeraUser{
                    id: user.id.to_hex(),
                    fullname: user.fullname,
                    role: user.role,
                    hash: user.hash,
                    salt: user.salt,
                    username: user.username
                });
            }

            #[derive(Serialize)]
            struct UsermanagementContext<'a> {
                jwt: &'a str,
                fullname: &'a str,
                user: Vec<TeraUser>,
                token: SecurityToken
            }

            return Template::render("user/management", UsermanagementContext {
                jwt: token_value.value(),
                fullname: fullname_value.value(),
                user: user_list_tera,
                token: t
            });
        },
        None => {
            return  Template::render("unauthorized", context!{});
        }
    }
}

#[derive(FromForm)]
pub struct NewUser<'r> {
    #[field(validate = len(1..))]
    pub fullname:  &'r str,
    #[field(validate = len(1..))]
    pub username:  &'r str,
    #[field(validate = len(1..))]
    pub password:  &'r str,
    #[field(validate = len(1..))]
    pub role:  &'r str
}

#[post("/usermanagement/add", data="<new_user>")]
pub async fn create_new_user(cookies: &CookieJar<'_>, new_user: Form<NewUser<'_>>) -> Json<UserResult> {
    
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
                return Json(UserResult{
                    status: 0
                });
            }

            let salt = create_salt();
            let pw = new_user.password.to_string() + &salt;
            let hash = create_hash(&pw);

            let user_instance = User {
                id: ObjectId::new(),
                username: new_user.username.to_string(),
                role: new_user.role.to_string(),
                fullname: new_user.fullname.to_string(),
                salt: salt,
                hash: hash
            };

            let database = get_standard_database().await;
            let r = add_new_user(&database, &user_instance).await;

            match r {
                Ok(o) => {
                    return Json(UserResult{
                        status: 1
                    });
                },
                Err(e) => {
                    return Json(UserResult{
                        status: 0
                    });
                }
            }
            
        },
        None => {
            return Json(UserResult{
                status: 0
            });
        }
    }
}

#[get("/usermanagement/remove/<id>")]
pub async fn delete_existing_user(cookies: &CookieJar<'_>, id: String) -> Json<UserResult> {
    
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
                return Json(UserResult{
                    status: 0
                });
            }

            let database = get_standard_database().await;
            let r = remove_user_by_id(&database, &ObjectId::parse_str(&id).unwrap()).await;

            match r {
                Ok(o) => {
                    return Json(UserResult{
                        status: 1
                    });
                },
                Err(e) => {
                    return Json(UserResult{
                        status: 0
                    });
                }
            }
            
        },
        None => {
            return Json(UserResult{
                status: 0
            });
        }
    }
}

pub fn create_salt() -> String {
    let rand_string: String = thread_rng()
    .sample_iter(&Alphanumeric)
    .take(30)
    .map(char::from)
    .collect();

    return rand_string;

}

#[launch]
fn rocket() -> _ {

    rocket::build()
        .mount("/", routes![
            list_all_user
    ]).attach(Template::fairing())
}

#[cfg(test)]
mod tests {

    use super::rocket;
    use rocket::http::Status;
    use rocket::local::asynchronous::Client;

    #[tokio::test]
    async fn test_user_list() {
        let client = Client::tracked(rocket()).await.expect("valid rocket instance");
        let mut response = client.get(uri!(super::list_all_user)).dispatch();
        assert_eq!(response.await.status(), Status::Ok);
    }

    #[tokio::test]
    async fn test_salt_creator() {
        let salt = super::create_salt();
        assert_eq!(salt.chars().count(),30);
    }
}