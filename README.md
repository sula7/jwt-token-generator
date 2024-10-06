# Test task BackDev

Just random test task found in the internet :)

#### <span style="color:red">DISCLAIMER</span>

The author of this repository does not grant any permission to use any part of the code in this repository for
completing test tasks.  
I am not responsible for anyone who uses the code from this repository to complete test assignments. I just found this
task in the public domain and decided to implement it

## Technologies used in the project

* Go
* JWT
* PostgreSQL

## Task

Implement auth service

### HTTP endpoints:

The first route returns a pair of Access and Refresh tokens for the user with the identifier (UUID v4) specified in the
request parameter.  
The second route performs a Refresh operation on the pair of Access and Refresh tokens

## Requirements

The Access token is of type JWT, uses the SHA512 algorithm, and storing it in the database is strictly prohibited.
The Refresh token is of arbitrary type, transmitted in base64 format, and stored in the database exclusively as a bcrypt
hash. It must be protected from client-side modifications and from attempts at reuse.
The Access and Refresh tokens are mutually linked, and the Refresh operation for the Access token can only be performed
using the same Refresh token that was issued with it.
The token payloads must contain information about the client’s IP address to which they were issued. If the IP address
changes during the refresh operation, an email warning should be sent to the user’s email (for simplification, mock data
can be used).

## Result

The result of the assignment must be provided in the form of source code on GitHub. It will be a plus if you manage to
use Docker and cover the code with tests

## Env

### Required

```shell
POSTGRES_DSN=postgres://user:pwd@host:port/db
TOKEN_SECRET=foobar # any string
```

### Optional

```shell
LOG_LEVEL=debug # default is info
LISTEN_ADDR=:1234 # default is :8080
ACCESS_TOKEN_TTL=5m # go duration format; default is 30m
REFRESH_TOKEN_TTL=24h # go duration format; default is 2h
```

## Run

1. Startup PostgreSQL database
2. Setup env vars
3. Start the app
4. Add manually user into `users` table
5. Make GET request to `/:user_id/token` to obtain tokens pair
6. Make POST request with current refresh token in the header `Bearer + token` to `/:user_id/token/refresh` to refresh
   previous token (get a new pair of tokens)

## TODO

- [x] Basic implementation
- [ ] Write unit tests
- [ ] Wrap to Docker
- [ ] Add linter
