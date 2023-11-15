CREATE TABLE posts (
    id Serial PRIMARY KEY,
    created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_name Varchar(30) NOT NULL,
    title Varchar(100) NOT NULL,
    content Varchar(300) NOT NULL
)