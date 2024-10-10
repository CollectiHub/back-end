# back-end

## Running (testing)

To run testing API you need to add appropriate `.env.docker` file (use `.env.sample` as example)
and run `docker compose --profile testing up -d` command. It will start database and
API server (on port `4000`).

You will be able to access API server on `http://localhost:4000/api/v1/` and swagger
documentation on `http://localhost:4000/api/v1/swagger/`.

## Running (development)

Main file of the application is `cmd/api/main.go`. So if you want to run,
build or install the application, you need to work with that file.

- To build application you need to use `go build cmd/api/main.go` command with
  the main file. And then you'll be able to run the application binary.
- To run application you can use `go run cmd/api/main.go` command with the main file.

It's also important to start your database and fill environment
file using `.env.sample` as example.

## Structure

- `cmd/**/*` – root files of application that start server.
- `internal/*` – utility funcions that help with business logic,
  constants and other stuff
- `types/*` – common types
- `api/middleware/*` – application's API middleware
- `api/models/*` – database models (augmented with ORM), their
  related DTOs and supportive functions
- `api/router/*` – application routers
