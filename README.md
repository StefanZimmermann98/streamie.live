# rust_stream_service

FWPM Projekt Rust Gruppe 1

## Name
Streamie - Webplatform for interactive stream management - Written in Rust

## Description
Development of an on-premise web application for managing one-to-many streams. It is intended to authenticate regular users and stream providers as user groups. Users see "events" and can enter them. An event has an embedded Vimeo/Youtube stream and additional information. Administrators can create events, add Vimeo/Youtube links, and edit the information. The frontend should be written with Rust Webassembly, the server backend with Rust and primarily Rocket.rs. During an event administrators can view meta data like the number of visitors or similar.


## Roadmap

- [x] JWT Authentification with CAPTCHA-check
- [x] Encrypted Cookies
- [x] User and Session Administration
- [x] Twitch and Youtube Support
- [x] Live-Chat
- [x] 3 distinct Roles
- [ ] dynamic Roles
- [ ] Vimeo Support
- [ ] Metrics of stream consumer
- [ ] Additional session data (e.g. downloadable files)  

## Contributing

Open Contributor group. Help if you want to.

## Authors and acknowledgment

Robin Goldbach
Maximilian Hanusch
Stefan Zimmermann

## License

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Project status

Currently in development state.

## Installation

- Clone the repository or download source code
- Modify it (e.g. corporate design in /static/streamie.css, ...)
```
$cargo run
```

## Setup Mongodb

- Install MongoDB
- Create Two Databases, one for the main application called 'Streamie', the other one for tests called 'Test'
- It might be needed to adjust the mongodb URL in the database.rs class if its not regular locally hosted

## Run the tests

```
$cargo test
```
  
## Ship it to an server

- Ship source code to the destination server
  
```
$cargo build --release
```

Add your systemd configuration and enable it. A example configuration should look like this:

```
[Unit]
Description=Rust Studienprojekt Service

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/streamie.live
Environment="ROCKET_ENV=prod"
Environment="ROCKET_ADDRESS=127.0.0.1"
Environment="ROCKET_PORT=10101"
Environment="ROCKET_LOG=critical"
ExecStart=/var/www/streamie.live/target/release/rust_stream_service

[Install]
WantedBy=multi-user.target
```

Start the service on your destination server.

```
$sudo systemctl start streamie.live
```

## Host it by yourself

The application was tested with an nginx reverse proxy on ubuntu 20.04 LTS.
Your nginx configuration should look like this:
```
server {
    listen 80; # Only if sysctl net.ipv6.bindv6only = 1
    listen [::]:80;

    # Your domain names.
    server_name streamie.live;

    # redirect to https version of the site
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl; # Only if sysctl net.ipv6.bindv6only = 1
    listen [::]:443 ssl;

    # Your domain names (same as in the http block)
    server_name streamie.live;

    ## SSL settings
    ssl_certificate /etc/letsencrypt/live/streamie.live/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/streamie.live/privkey.pem;
    ssl_session_timeout 5m;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2; # don't use SSLv3. Ref: POODLE
    ssl_prefer_server_ciphers on;

    location / {
        # Forward requests to rocket
        proxy_set_header Host $host;

        # Change your port with the release port chosen in the Rocket.toml
        proxy_pass http://0.0.0.0:10101;

        # Settings are required for Chat using server-sent-events
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_buffering off;
        proxy_cache off;
    }
}
```


