package errors

import (
	"github.com/CriticalSecurity/cc-scanner/internal/config"
	"github.com/getsentry/sentry-go"
	"log"
	"os"
)

func HandleError(err error, msg string){
	configFile := os.Getenv("CONFIGFILE")
	appConfiguration := config.LoadConfiguration(configFile)
	if appConfiguration.SentryIoDsn != "" {
		sentry.CaptureException(err)
		sentry.CaptureMessage(msg)
	}
	log.Printf("Error: %s\n", msg)
}

