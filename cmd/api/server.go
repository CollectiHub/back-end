package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func (app *application) serve() error {
	srv := &http.Server{
		Addr:         fmt.Sprintf("0.0.0.0:%d", app.config.Port),
		Handler:      app.routes(),
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// Create a shutdownError channel. It is used to receive
	// any errors returned by the graceful Shutdown() function.
	shutdownError := make(chan error)

	// Start a background goroutine.
	go func() {
		// Create a quit channel which carries os.Signal values. Use buffered
		quit := make(chan os.Signal, 1)

		// Use signal.Notify() to listen for incoming SIGINT and SIGTERM signals and relay
		// them to the quit channel. Any other signal will not be caught by signal.Notify()
		// and will retain their default behavior.
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

		// Read the signal from the quit channel. This code will block until a signal is
		// received.
		s := <-quit

		app.logger.Info().Msgf("caught signal: %s", s.String())

		// Create a context with a 5-second timeout.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// call Shutdown on the server, and only send on the shutdownError channel if it returns
		// an error
		err := srv.Shutdown(ctx)
		if err != nil {
			shutdownError <- err
		}

		// Log a message to say that we're waiting for any background goroutines to complete
		// their tasks.
		app.logger.Info().Msgf("completing background tasks on addr: %s", srv.Addr)

		// Call Wait() to block until our WaitGroup counter is zero. This essentially blocks
		// until the background goroutines have finished. Then we return nil on the shutdownError
		// channel to indicate that the shutdown as compleeted without any issues.
		app.wg.Wait()
		shutdownError <- nil
	}()

	// Log a "starting server" message.
	app.logger.Info().Msgf("Starting server on %s with [%s] environment", srv.Addr, app.config.Env)

	// Calling Shutdown() on our server will cause ListenAndServer() to immediately
	// return a http.ErrServerClosed error. So, if we see this error, it is actually a good thing
	// and an indication that the graceful shutdown has started. So, we specifically check for this,
	// only returning the error if it is NOT http.ErrServerClosed.
	err := srv.ListenAndServe()
	if !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	// Otherwise, we wait to receive the return value from Shutdown() on the shutdownErr
	// channel. If the return value is an error, we know that there was a problem with the
	// graceful shutdown, and we return the error.
	err = <-shutdownError
	if err != nil {
		return err
	}

	// At this point we know that the graceful shutdown completed successfully, and we log
	// a "stopped server" message.
	app.logger.Info().Msgf("stopped server on %s", srv.Addr)

	return nil
}
