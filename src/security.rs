use hmac::{Hmac, Mac};
use jwt::{SignWithKey, Header, Token, VerifyWithKey};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};
use rocket_dyn_templates::{Template};
use rocket::http::{Cookie, CookieJar};
use rocket::response::{Flash, Redirect};
use std::collections::HashMap;
use captcha_rs::CaptchaBuilder;
use rocket::form::Form;
use crate::database::{get_client, get_standard_database, get_user_by_username_and_password};
use crate::sessions::{User};
use rocket::serde::Serialize;

// Aktuell unterstützt die Anwendung 3 Rollen -> Admin sieht Admin-Panel, 
// Moderator wird nur im Chat speziell markiert
#[derive(Serialize)]
#[derive(PartialEq)] // Wird benötigt um einen == Vergleich machen zu können
pub enum SecurityRole {
    ADMIN,
    USER,
    MODERATOR,
}

// Transform-Struct für den JSON-Web-Token
#[derive(Serialize)]
pub struct SecurityToken {
    pub username: String,
    pub role: SecurityRole,
    pub iss: String,
    pub iat: u64,
    pub exp: u64,
}

// Token-Creator
// RustProjektarbeit2022 ist das Token Secret
// TODO: sollte konfigurierbar sein
pub fn create_token(sec_token: SecurityToken) -> String {
    let key: Hmac<Sha256> = Hmac::new_from_slice(b"WRITEYOURSECRETHERE").unwrap();
    let mut claims = BTreeMap::new();

    claims.insert("username", sec_token.username);

    let role = match sec_token.role {
        SecurityRole::ADMIN => "ADMIN",
        SecurityRole::MODERATOR => "MODERATOR",
        _ => "USER"
    };

    claims.insert("role", role.to_string());

    claims.insert("iss", sec_token.iss);

    claims.insert("iat", sec_token.iat.to_string());
    claims.insert("exp", sec_token.exp.to_string());

    let token_str = claims.sign_with_key(&key).unwrap();
    return token_str.to_string();
}

// Token-Validator
// RustProjektarbeit2022 ist das Token Secret
// TODO: sollte konfigurierbar sein
pub fn validate_token(token: String) -> Option<SecurityToken> {
    let key: Hmac<Sha256> = Hmac::new_from_slice(b"WRITEYOURSECRETHERE").unwrap();
    let token_str = token.as_str();

    // Hier fliegt ein panic wenn das nicht klappt, sollte nochmal besser behandelt werden
    let tmp_token: Result<Token<Header, BTreeMap<String, String>, _>, jwt::Error> = VerifyWithKey::verify_with_key(token_str, &key);
    
    match tmp_token {
        Ok(v) => {
            let decoded_token = v;

            let header = decoded_token.header();
            let claims = decoded_token.claims();
        
            // Zeit-Werte liegen im JWT als Strings vor -> müssen zu u64 geparst werden
            let exp: u64 = claims.get("exp").unwrap().parse().unwrap();
            let current_time = SystemTime::now().duration_since(UNIX_EPOCH).expect("Current Time for token validation not receivable").as_secs();
            if exp < current_time {
                return Option::None;
            }
        
            let sec_role: SecurityRole;

            // Map String to Role
            match claims.get("role").unwrap().to_string().as_str() {
                "ADMIN" => sec_role = SecurityRole::ADMIN,
                "MODERATOR" => sec_role = SecurityRole::MODERATOR,
                _ => sec_role = SecurityRole::USER
            };

            let issuer = claims.get("iss").unwrap().to_string();
            if issuer != "streamie.live".to_string() {
                return Option::None;
            }
            
            // Erzeuge ein SecurityToken Objekt
            let security_token = SecurityToken {
                username: claims.get("username").unwrap().to_string(),
                role: sec_role,
                iss: issuer,
                iat: claims.get("iat").unwrap().parse().unwrap(),
                exp: exp,
            };
        
            return Option::from(security_token);
        },
        Err(e) => return Option::None
    }
}

// Standard Login-Page
#[get("/login")]
pub async fn login(cookies: &CookieJar<'_>) -> Template {

    #[derive(Serialize)]
    struct LoginContext<'a> {
        jwt: &'a str,
        fullname: &'a str,
        captcha: &'a String,
    }

    let c = CaptchaBuilder::new()
        .length(5)
        .width(130)
        .height(40)
        .dark_mode(true)
        .complexity(1)
        .build();

    // Speicher Captcha um Ihn beim Login vergleichen zu können
    cookies.add_private(Cookie::new("captcha", c.text));

    return Template::render("login", LoginContext {
        jwt:"None",
        fullname:"Unknown User",
        captcha: &c.base_img
    });

}


// Form-Guard für den Post-Body
// sowohl Username als auch Passwort müssen > 1 sein
#[derive(FromForm)]
pub struct LoginUser<'r> {
    #[field(validate = len(1..))]
    user: &'r str,
    #[field(validate = len(1..))]
    pass: &'r str,
    #[field(validate = len(1..))]
    captcha: &'r str
}

// Ziel der Login-Prüfung
#[post("/login/proceed", data = "<loginuser>")]
pub async fn login_proceed(loginuser: Form<LoginUser<'_>>, cookies: &CookieJar<'_>) -> &'static str {

    // Prüfe den zuvor gespeicherten Captcha
    let captcha: Option<Cookie> = cookies.get_private("captcha");
    let captcha = match captcha {
        Some(captcha_value) => String::from(captcha_value.value()),
        None => String::new()
    };

    if captcha != String::from(loginuser.captcha) {
        return "Not Authorized";
    }

    // Suche in der Datenbank nach dem User mit dem entsprechenden Passwort
    let database = get_standard_database().await;
    let possible_user: Option<User> = get_user_by_username_and_password(&database, &loginuser.user.to_string(), loginuser.pass.to_string()).await;

    // Falls User gefunden
    match possible_user {
        Some(v) => {
            // Erzeuge neue Cookies mit dem JWT
            cookies.add_private(Cookie::new("fullname", v.fullname));

            let security_token = SecurityToken {
                username: v.username,
                role: if v.role == "ADMIN" {
                    SecurityRole::ADMIN
                } else if v.role == "MODERATOR" {
                    SecurityRole::MODERATOR
                } else {
                    SecurityRole::USER
                },
                iss: String::from("streamie.live"),
                iat: SystemTime::now().duration_since(UNIX_EPOCH).expect("IAT-Time for token not receivable").as_secs(),
                exp: SystemTime::now().duration_since(UNIX_EPOCH).expect("IAT-Time for token not receivable").as_secs() + 7200,
            };
            
            // streamie.live ist der Standard-Cookie für den Auth-Token
            cookies.add_private(Cookie::new("streamie.live", create_token(security_token)));
            return "Eingeloggt";
        },
        None => {
            // Falls User oder Passwort falsch
            return "Not Authorized";
        }
    }

    
}

// Lösche den Auth Token und mache einen Redirect
#[get("/logout")]
pub fn logout(cookies: &CookieJar<'_>) -> Flash<Redirect> {
    cookies.remove_private(Cookie::named("streamie.live"));
    Flash::success(Redirect::to("/"), "Successfully logged out.")
}

#[cfg(test)]
mod tests {

    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_token_create_validate() {
        let st = super::SecurityToken {
            username: "Testuser".to_string(),
            role: super::SecurityRole::MODERATOR,
            iss: "streamie.live".to_string(),
            iat: SystemTime::now().duration_since(UNIX_EPOCH).expect("IAT-Time for token not receivable").as_secs(),
            exp: SystemTime::now().duration_since(UNIX_EPOCH).expect("IAT-Time for token not receivable").as_secs() + 300,
        };

        let st_token = super::create_token(st);
        match super::validate_token(st_token) {
            Some(e) => assert_eq!(true,true),
            None => assert_eq!(true,false)
        }
    }

    #[test]
    fn test_token_is_invalid_issuer() {
        let st = super::SecurityToken {
            username: "Testuser".to_string(),
            role: super::SecurityRole::MODERATOR,
            iss: "nicht-streamie".to_string(),
            iat: SystemTime::now().duration_since(UNIX_EPOCH).expect("IAT-Time for token not receivable").as_secs(),
            exp: SystemTime::now().duration_since(UNIX_EPOCH).expect("IAT-Time for token not receivable").as_secs() + 300,
        };

        let st_token = super::create_token(st);
        match super::validate_token(st_token) {
            Some(e) => assert_eq!(true,false),
            None => assert_eq!(true,true)
        }
    }

    #[test]
    fn test_token_is_invalid_time() {
        let st = super::SecurityToken {
            username: "Testuser".to_string(),
            role: super::SecurityRole::MODERATOR,
            iss: "streamie.live".to_string(),
            iat: SystemTime::now().duration_since(UNIX_EPOCH).expect("IAT-Time for token not receivable").as_secs(),
            exp: 300,
        };

        let st_token = super::create_token(st);
        match super::validate_token(st_token) {
            Some(e) => assert_eq!(true,false),
            None => assert_eq!(true,true)
        }
    }
}
