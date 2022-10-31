package commands

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/pki"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/errs"
	"go.step.sm/cli-utils/step"
)

// AppCommand is the action used as the top action.
var AppCommand = cli.Command{
	Name:   "start",
	Action: appAction,
	UsageText: `**step-ca** <config> [**--password-file**=<file>]
[**--ssh-host-password-file**=<file>] [**--ssh-user-password-file**=<file>]
[**--issuer-password-file**=<file>] [**--resolver**=<addr>]`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: "password-file",
			Usage: `path to the <file> containing the password to decrypt the
intermediate private key.`,
		},
		cli.StringFlag{
			Name: "ssh-host-password-file",
			Usage: `path to the <file> containing the password to decrypt the
private key used to sign SSH host certificates. If the flag is not passed it
will default to --password-file.`,
		},
		cli.StringFlag{
			Name: "ssh-user-password-file",
			Usage: `path to the <file> containing the password to decrypt the
private key used to sign SSH user certificates. If the flag is not passed it
will default to --password-file.`,
		},
		cli.StringFlag{
			Name: "issuer-password-file",
			Usage: `path to the <file> containing the password to decrypt the
certificate issuer private key used in the RA mode.`,
		},
		cli.StringFlag{
			Name:  "resolver",
			Usage: "address of a DNS resolver to be used instead of the default.",
		},
		cli.StringFlag{
			Name:   "token",
			Usage:  "token used to enable the linked ca.",
			EnvVar: "STEP_CA_TOKEN",
		},
		cli.BoolFlag{
			Name:   "quiet",
			Usage:  "disable startup information",
			EnvVar: "STEP_CA_QUIET",
		},
		cli.StringFlag{
			Name:   "context",
			Usage:  "The name of the authority's context.",
			EnvVar: "STEP_CA_CONTEXT",
		},
	},
}

// AppAction is the action used when the top command runs.
func appAction(ctx *cli.Context) error {
	passFile := ctx.String("password-file")
	sshHostPassFile := ctx.String("ssh-host-password-file")
	sshUserPassFile := ctx.String("ssh-user-password-file")
	issuerPassFile := ctx.String("issuer-password-file")
	resolver := ctx.String("resolver")
	token := ctx.String("token")
	quiet := ctx.Bool("quiet")

	if ctx.NArg() > 1 {
		return errs.TooManyArguments(ctx)
	}

	if caCtx := ctx.String("context"); caCtx != "" {
		if err := step.Contexts().SetCurrent(caCtx); err != nil {
			return err
		}
	}

	var configFile string
	if ctx.NArg() > 0 {
		configFile = ctx.Args().Get(0)
	} else {
		configFile = step.CaConfigFile()
	}

	cfg, err := config.LoadConfiguration(configFile)
	if err != nil && token == "" {
		fatal(err)
	}

	// Initialize a basic configuration to be used with an automatically
	// configured linked RA. Default configuration includes:
	//  * badgerv2 on $(step path)/db
	//  * JSON logger
	//  * Default TLS options
	if cfg == nil {
		cfg = &config.Config{
			SkipValidation: true,
			Logger:         []byte(`{"format":"json"}`),
			DB: &db.Config{
				Type:       "badgerv2",
				DataSource: filepath.Join(step.Path(), "db"),
			},
			AuthorityConfig: &config.AuthConfig{
				DeploymentType: pki.LinkedDeployment.String(),
				Provisioners:   provisioner.List{},
				Template:       &config.ASN1DN{},
				Backdate: &provisioner.Duration{
					Duration: config.DefaultBackdate,
				},
			},
			TLS: &config.DefaultTLSOptions,
		}
	}

	if cfg.AuthorityConfig != nil {
		if token == "" && strings.EqualFold(cfg.AuthorityConfig.DeploymentType, pki.LinkedDeployment.String()) {
			return errors.New(`'step-ca' requires the '--token' flag for linked deploy type.

To get a linked authority token:
  1. Log in or create a Certificate Manager account at ` + "\033[1mhttps://u.step.sm/linked\033[0m" + `
  2. Add a new authority and select "Link a step-ca instance"
  3. Follow instructions in browser to start 'step-ca' using the '--token' flag
`)
		}
	}

	var password []byte
	if passFile != "" {
		if password, err = os.ReadFile(passFile); err != nil {
			fatal(errors.Wrapf(err, "error reading %s", passFile))
		}
		password = bytes.TrimRightFunc(password, unicode.IsSpace)
	}

	var sshHostPassword []byte
	if sshHostPassFile != "" {
		if sshHostPassword, err = os.ReadFile(sshHostPassFile); err != nil {
			fatal(errors.Wrapf(err, "error reading %s", sshHostPassFile))
		}
		sshHostPassword = bytes.TrimRightFunc(sshHostPassword, unicode.IsSpace)
	}

	var sshUserPassword []byte
	if sshUserPassFile != "" {
		if sshUserPassword, err = os.ReadFile(sshUserPassFile); err != nil {
			fatal(errors.Wrapf(err, "error reading %s", sshUserPassFile))
		}
		sshUserPassword = bytes.TrimRightFunc(sshUserPassword, unicode.IsSpace)
	}

	var issuerPassword []byte
	if issuerPassFile != "" {
		if issuerPassword, err = os.ReadFile(issuerPassFile); err != nil {
			fatal(errors.Wrapf(err, "error reading %s", issuerPassFile))
		}
		issuerPassword = bytes.TrimRightFunc(issuerPassword, unicode.IsSpace)
	}

	// replace resolver if requested
	if resolver != "" {
		net.DefaultResolver.PreferGo = true
		net.DefaultResolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.Dial(network, resolver)
		}
	}

	srv, err := ca.New(cfg,
		ca.WithConfigFile(configFile),
		ca.WithPassword(password),
		ca.WithSSHHostPassword(sshHostPassword),
		ca.WithSSHUserPassword(sshUserPassword),
		ca.WithIssuerPassword(issuerPassword),
		ca.WithLinkedCAToken(token),
		ca.WithQuiet(quiet))
	if err != nil {
		fatal(err)
	}

	go ca.StopReloaderHandler(srv)
	if err = srv.Run(); err != nil && err != http.ErrServerClosed {
		fatal(err)
	}
	return nil
}

// fatal writes the passed error on the standard error and exits with the exit
// code 1. If the environment variable STEPDEBUG is set to 1 it shows the
// stack trace of the error.
func fatal(err error) {
	if os.Getenv("STEPDEBUG") == "1" {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
	} else {
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(2)
}
