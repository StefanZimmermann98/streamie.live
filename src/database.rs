use chrono::{DateTime, NaiveDateTime, Utc};
use futures::{StreamExt, TryFutureExt, TryStreamExt};
use mongodb::bson::{Bson, doc, Document, to_bson};
use mongodb::bson::oid::ObjectId;
use mongodb::Client;
use mongodb::options::{ClientOptions, DatabaseOptions};
use rocket::http::ext::IntoCollection;
use sha2::{Sha256, Digest};
use crate::security::SecurityRole;
use crate::sessions::{Session, SessionStream, StreamType, User};

pub const DATABASE_NAME: &str = "Streamie";
pub const TEST_DATABASE_NAME: &str = "Test";

pub const USERS_COLLECTION: &str = "users";
pub const SESSIONS_COLLECTION: &str = "sessions";

// Holt sich einen mongodb client
pub async fn get_client() -> mongodb::Client {
    let mut client_options = ClientOptions::parse("mongodb://localhost:27017")
        .await
        .unwrap();

    let client = Client::with_options(client_options)
        .unwrap();

    return client;
}

// Holt die standard Streamie Datenbank
pub async fn get_standard_database() -> mongodb::Database {
    return get_database_by_name(&DATABASE_NAME).await;
}

// Holt eine Datenbank nach namen
pub async fn get_database_by_name(name: &str) -> mongodb::Database {
    let client = get_client().await;
    return client.database(&name);
}

// hinzufügen eines neuen Users
pub async fn add_new_user(database: &mongodb::Database, user: &User) -> mongodb::error::Result<()> {
    let collection = database.collection::<User>(&USERS_COLLECTION);

    // Filter nach dem username
    let filter = doc! {"username": &user.username};
    let opt_user = collection.find_one(filter, None)
        .await
        .expect("error while find");

    // der username ist unique, wenn er schon vorhanden ist soll gepanict werden
    if opt_user.is_some() {
        panic!("Found Users with given username while adding, but has to be unique.");
    }

    collection.insert_one(user, None).await?;

    Ok(())
}

// hinzufügen einer neuer session
pub async fn add_new_session(database: &mongodb::Database, session: &Session) -> mongodb::error::Result<()> {
    let collection = database.collection::<Session>(&SESSIONS_COLLECTION);

    collection.insert_one(session, None).await?;

    Ok(())
}

// updaten einer session
pub async fn update_session(database: &mongodb::Database, session: &Session) -> mongodb::error::Result<()> {
    let collection = database.collection::<Session>(&SESSIONS_COLLECTION);

    let filter = doc! {"_id": &session.id};

    collection.update_one(filter, construct_session_update_doc(&session), None).await?;

    Ok(())
}

// Wir benutzt um ein session document zu bauen mitdem dann das bestehende mongodb dokukment
// aktualisiert wird
fn construct_session_update_doc(session: &Session) -> Document {
    return doc!{"$set": {
            "start": session.start.to_string(),
            "end": session.end.to_string(),
            "name": &session.name,
            "description": &session.description,
            "stream": to_bson(&session.stream).unwrap()
            }
    };
}

// löschen einer session per id
pub async fn remove_session_by_id(database: &mongodb::Database, id: &ObjectId) -> mongodb::error::Result<()> {
    let collection = database.collection::<Session>(&SESSIONS_COLLECTION);

    let filter = doc! {"_id": &id};
    collection.delete_one(filter, None).await?;

    Ok(())
}

// löschen eines users per id
pub async fn remove_user_by_id(database: &mongodb::Database, id: &ObjectId) -> mongodb::error::Result<()> {
    let collection = database.collection::<User>(&USERS_COLLECTION);

    let filter = doc! {"_id": &id};
    collection.delete_one(filter, None).await?;

    Ok(())
}

pub async fn remove_session_by_name(database: &mongodb::Database, name: String) -> mongodb::error::Result<()> {
    let collection = database.collection::<Session>(&SESSIONS_COLLECTION);

    let filter = doc! {"name": &name};
    collection.delete_one(filter, None).await?;

    Ok(())
}

// Sammeln aller user in der Datenbank
pub async fn get_all_users(database: &mongodb::Database) -> Vec<User> {
    let collection = database.collection::<User>(&USERS_COLLECTION);

    let mut cursor = collection.find(None, None)
        .await
        .expect("Error while find");

    let mut users: Vec<User> = vec![];

    while let Some(user) = cursor.try_next()
        .await
        .expect("Error while processing Cursor") {
        users.push(user);
    }

    return users;
}

// Sammeln aller sessions in der Datenbank
pub async fn get_all_sessions(database: &mongodb::Database) -> Vec<Session> {
    let collection = database.collection::<Session>(&SESSIONS_COLLECTION);

    let mut cursor = collection.find(None, None)
        .await
        .expect("Error while find");

    let mut sessions: Vec<Session> = vec![];

    while let Some(session) = cursor.try_next()
        .await
        .expect("Error while processing Cursor") {
        sessions.push(session);
    }

    return sessions;
}

// holt sich die session per id
pub async fn get_session_by_id(database: &mongodb::Database, id: &ObjectId) -> Session {
    let collection = database.collection::<Session>(&SESSIONS_COLLECTION);

    let filter = doc! {"_id": id};
    let mut cursor = collection.find_one(filter, None)
        .await
        .expect("Error while find");

    return cursor.unwrap();
}

pub async fn get_session_by_name(database: &mongodb::Database, name: String) -> Session {
    let collection = database.collection::<Session>(&SESSIONS_COLLECTION);

    let filter = doc! {"name": name};
    let mut cursor = collection.find_one(filter, None)
        .await
        .expect("Error while find");

    return cursor.unwrap();
}

// verifizierungs methode
pub async fn get_user_by_username_and_password(database: &mongodb::Database, username: &String,
                                               password: String) -> Option<User> {

    let collection = database.collection::<User>(&USERS_COLLECTION);

    let filter = doc! {"username": username};
    let mut cursor = collection.find_one(filter, None)
        .await
        .expect("Error while find");


    let user = cursor.unwrap();


    let pw_hash = &user.hash;
    let hash_with_salt = password + &user.salt;
    let hashed = create_hash(&hash_with_salt);

    // vergleiche den neuen hash mit dem in der datenbank
    if pw_hash.eq(&hashed) {
        return Some(user);
    }

    return None;
}

// erstellen des hashes
pub fn create_hash(value: &String) -> String {
    let mut hash = sha2::Sha256::new();
    hash.update(value.as_bytes());
    return format!("{:x}", hash.finalize());
}

#[cfg(test)]
mod tests {
    use crate::add_session;
    use crate::usermanagement::create_salt;
    use super::*;

    pub const FORMAT_STR: &str = "%d.%m.%Y %H:%M:%S";

    #[tokio::test]
    async fn test_add_user() {
        let database = get_database_by_name(TEST_DATABASE_NAME).await;

        let test_user = get_test_user("test_add_user_name".to_string());

        let result = add_new_user(&database, &test_user).await;
        assert!(result.is_ok());

        remove_user_by_id(&database, &test_user.id).await;
    }

    #[tokio::test]
    async fn test_add_session() {
        let database = get_database_by_name(TEST_DATABASE_NAME).await;

        let test_session = get_test_session();

        let result = add_new_session(&database, &test_session).await;
        assert!(result.is_ok());

        remove_session_by_id(&database, &test_session.id).await;
    }

    #[tokio::test]
    async fn test_remove_user() {
        let database = get_database_by_name(TEST_DATABASE_NAME).await;

        let test_user = get_test_user("test_get_user_name".to_string());

        add_new_user(&database, &test_user).await;

        let result = remove_user_by_id(&database, &test_user.id).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_remove_session() {
        let database = get_database_by_name(TEST_DATABASE_NAME).await;

        let test_session = get_test_session();

        add_new_session(&database, &test_session).await;

        let result = remove_session_by_id(&database, &test_session.id).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_user_by_username_and_password() {
        let database = get_database_by_name(TEST_DATABASE_NAME).await;

        let salt = create_salt();
        let pw = "password".to_string() + &salt;
        let hash = create_hash(&pw);

        let test_user = User {
            id: ObjectId::new(),
            username: "get_user_test_name".to_string(),
            hash: hash,
            salt: salt,
            role: "USER".to_string(),
            fullname: "fullname_test".to_string()
        };

        add_new_user(&database, &test_user).await;

        let opt_user = get_user_by_username_and_password(&database, &test_user.username, "password".to_string()).await;


        assert!(opt_user.is_some());
        let user = opt_user.unwrap();

        assert_eq!(&user.id, &test_user.id);
        assert_eq!(&user.username, &test_user.username);
        assert_eq!(&user.hash, &test_user.hash);
        assert_eq!(&user.salt, &test_user.salt);
        assert_eq!(&user.role, &test_user.role);
        assert_eq!(&user.fullname, &test_user.fullname);

        remove_user_by_id(&database, &test_user.id).await;
    }

    #[tokio::test]
    async fn test_get_session_by_id() {
        let database = get_database_by_name(TEST_DATABASE_NAME).await;

        let test_session = get_test_session();
        add_new_session(&database, &test_session).await;

        let session = get_session_by_id(&database, &test_session.id).await;

        assert_eq!(session.id, test_session.id);
        assert_eq!(session.start, test_session.start);
        assert_eq!(session.end, test_session.end);
        assert_eq!(session.name, test_session.name);
        assert_eq!(session.description, test_session.description);
        assert_eq!(session.stream.link, test_session.stream.link);

        remove_session_by_id(&database, &test_session.id).await;
    }

    #[tokio::test]
    async fn test_update_session() {
        let database = get_database_by_name(TEST_DATABASE_NAME).await;

        let mut test_session = get_test_session();
        add_new_session(&database, &test_session).await;

        test_session.name = "new_name".to_string();
        test_session.description = "new_description".to_string();

        let result = update_session(&database, &test_session).await;

        assert!(result.is_ok());

        let new_session = get_session_by_id(&database, &test_session.id).await;

        assert_eq!(new_session.name, "new_name".to_string());
        assert_eq!(new_session.description, "new_description".to_string());

        remove_session_by_id(&database, &test_session.id).await;
    }

    fn get_test_session() -> Session {
        let test_stream = SessionStream {
            link: "".to_string(),
            channel: "".to_string(),
            stream_type: StreamType::Twitch
        };

        let test_session = Session {
            id: ObjectId::new(),
            start: DateTime::<Utc>::from_utc(NaiveDateTime::parse_from_str(
                "09.07.2022 07:48:15", FORMAT_STR).expect("failed to parse startDateTime"),
                                             Utc),
            end: DateTime::<Utc>::from_utc(NaiveDateTime::parse_from_str(
                "09.07.2022 08:48:15", FORMAT_STR).expect("failed to parse startDateTime"),
                                           Utc),
            name: "".to_string(),
            description: "".to_string(),
            stream: test_stream
        };
        test_session
    }

    fn get_test_user(username: String) -> User {
        let test_user = User {
            id: ObjectId::new(),
            username: username,
            hash: "test_hash".to_string(),
            salt: "test_salt".to_string(),
            role: "USER".to_string(),
            fullname: "fullname_test".to_string()
        };
        test_user
    }
}