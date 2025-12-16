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

const (
	encryptedKeyType = "encrypted-hppk"
	exampleGenKey    = "qsh genkey -o ./id_hppk"
	exampleServer    = "qsh server --clients-config /etc/qsh/clients.json"
	exampleClient    = "qsh -i ./id_hppk -n client-1 127.0.0.1:2222"
	exampleCopy      = "qsh copy ./file client-1@203.0.113.10:/tmp/file"
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
					&cli.StringFlag{Name: "listen", Aliases: []string{"l"}, Value: ":2222", Usage: "listen address (default :2222)"},
					&cli.StringSliceFlag{Name: "client", Aliases: []string{"c"}, Usage: "allowed client entry in the form id=/path/to/id_hppk.pub (repeatable)"},
					&cli.StringFlag{Name: "clients-config", Aliases: []string{"C"}, Usage: "path to JSON file mapping client IDs to public keys"},
				},
				Action: runServerCommand,
			},
			{
				Name:   "copy",
				Usage:  "Securely copy files to/from a qsh server",
				Flags:  copyCLIFlags(),
				Action: runCopyCommand,
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

func copyCLIFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: "identity", Aliases: []string{"i"}, Value: "./id_hppk", Usage: "path to the HPPK private key"},
		&cli.StringFlag{Name: "id", Aliases: []string{"n"}, Value: "client-1", Usage: "client identifier presented during authentication"},
		&cli.IntFlag{Name: "port", Aliases: []string{"P"}, Value: 2222, Usage: "remote port when not specified in the target"},
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
