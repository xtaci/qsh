package main

import (
	"fmt"
	"log"
	"os"

	cli "github.com/urfave/cli/v2"
)

// sessionKeyBytes defines how many bytes of keying material we derive for each
// QPP pad direction.
const sessionKeyBytes = 256
const qppPadCount uint16 = 1019

const (
	encryptedKeyType = "encrypted-hppk"
	exampleGenKey    = "qsh genkey -o ./id_hppk"
	exampleServer    = "qsh server -l :2323 -c client-1=/etc/qsh/id_hppk.pub"
	exampleClient    = "qsh -i ./id_hppk -n client-1 127.0.0.1:2323"
)

// main dispatches between key generation, server mode, and client mode.
func main() {
	app := &cli.App{
		Name:  "qsh",
		Usage: "Secure remote shell using HPPK authentication and QPP encryption (client by default)",
		Flags: clientCLIFlags(),
		Commands: []*cli.Command{
			{
				Name:  "genkey",
				Usage: "Generate an HPPK keypair",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "output", Aliases: []string{"o"}, Usage: "path for the private key (public key stored as path.pub)", Required: true},
					&cli.IntFlag{Name: "strength", Aliases: []string{"s"}, Value: 8, Usage: "security parameter passed to HPPK key generation"},
				},
				Action: runGenKeyCommand,
			},
			{
				Name:  "server",
				Usage: "Run qsh in server mode",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "listen", Aliases: []string{"l"}, Usage: "listen address (e.g. :2323)", Required: true},
					&cli.StringSliceFlag{Name: "client", Aliases: []string{"c"}, Usage: "allowed client entry in the form id=/path/to/id_hppk.pub (repeatable)"},
				},
				Action: runServerCommand,
			},
		},
		Action: runClientCommand,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

// clientCLIFlags defines default client mode flags.
func clientCLIFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: "identity", Aliases: []string{"i"}, Value: "./id_hppk", Usage: "path to the HPPK private key"},
		&cli.StringFlag{Name: "id", Aliases: []string{"n"}, Value: "client-1", Usage: "client identifier presented during authentication"},
	}
}

// runGenKeyCommand handles the "genkey" CLI command.
func runGenKeyCommand(c *cli.Context) error {
	path := c.String("output")
	if path == "" {
		return exitWithExample("genkey command requires --output", exampleGenKey)
	}
	strength := c.Int("strength")
	if strength <= 0 {
		return exitWithExample("--strength must be a positive integer", exampleGenKey)
	}
	pass, err := promptPassword("Enter passphrase for new private key: ", true)
	if err != nil {
		return err
	}
	if len(pass) == 0 {
		return exitWithExample("passphrase cannot be empty", exampleGenKey)
	}
	defer clear(pass)
	if err := generateKeyPair(path, strength, pass); err != nil {
		return fmt.Errorf("%w\nExample: %s", err, exampleGenKey)
	}
	return nil
}

// exitWithExample formats an error message with an example and exits.
func exitWithExample(message, example string) error {
	return cli.Exit(fmt.Sprintf("%s\nExample: %s", message, example), 1)
}
