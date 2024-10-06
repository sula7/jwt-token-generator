CREATE TABLE users
(
    id uuid PRIMARY KEY
);

CREATE TABLE access_tokens
(
    token_id         uuid PRIMARY KEY,
    refresh_token_id uuid                        NOT NULL,
    user_id          uuid                        NOT NULL,
    ip_address       varchar                     NOT NULL,
    created_at       timestamp without time zone NOT NULL default now(),
    issued_at        timestamp without time zone NOT NULL,
    expires_at       timestamp without time zone,
    CONSTRAINT access_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE refresh_tokens
(
    token_id        uuid PRIMARY KEY,
    access_token_id uuid                        NOT NULL,
    user_id         uuid                        NOT NULL,
    ip_address      varchar                     NOT NULL,
    created_at      timestamp without time zone NOT NULL default now(),
    issued_at       timestamp without time zone NOT NULL,
    expires_at      timestamp without time zone,
    CONSTRAINT refresh_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES users (id)
);
