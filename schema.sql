CREATE TABLE IF NOT EXISTS "User" (
    user_id serial,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    first_name VARCHAR(255) NOT NULL,
    last_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    display_name VARCHAR(255) NOT NULL,
    spotify_refresh_token VARCHAR(512)
);


CREATE TABLE IF NOT EXISTS posts (
    id Serial PRIMARY KEY,
    created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_name Varchar(30) NOT NULL,
    title Varchar(100) NOT NULL,
    content Varchar(300) NOT NULL
); 