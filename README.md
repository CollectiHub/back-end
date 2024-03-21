# back-end

## Running

Main file of the application is `cmd/api/main.go`. So if you want to run,
build or install the application, you need to work with that file. 

- To start debug session with delve and Visual Studio Code you need
to use predefined launch configuration `Launch Package (debug)`.
- To build application you need to use `go build` command with
the main file.

It's also important to start your database and fill environment
file using `.env.sample` as example.

There is `docker-compose.yml` file that you can use to run database
with Docker.

## Structure

- `cmd/**/*` – root files of application that start server.
- `internal/*` – utility funcions that help with business logic,
constants and other stuff
- `types/*` – common types
- `api/middleware/*` – application's API middleware
- `api/models/*` – database models (augmented with ORM), their
related DTOs and supportive functions
- `api/router/*` – application routers