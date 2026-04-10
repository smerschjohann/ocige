package main

import (
	"context"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"
)

func main() {
	cmd := &cli.Command{
		Name:  "ocige",
		Usage: "Secure File Sharing over OCI Registries",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "insecure",
				Usage: "Use plain HTTP for registry",
			},
			&cli.StringFlag{
				Name:    "docker-config",
				Usage:   "Path to docker config.json",
				Sources: cli.EnvVars("DOCKER_CONFIG"),
			},
		},
		Commands: []*cli.Command{
			{
				Name:      "push",
				Usage:     "Pushes files to registry target",
				ArgsUsage: "<target> <file...>",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "recipients",
						Aliases: []string{"R"},
						Usage:   "Path to age recipients file",
						Sources: cli.EnvVars("OCIGE_RECIPIENTS"),
					},
					&cli.IntFlag{
						Name:  "chunk-size",
						Value: 2000,
						Usage: "Chunk size in MB",
					},
				},
				Action: handlePush,
			},
			{
				Name:      "pull",
				Usage:     "Pulls files from registry target",
				ArgsUsage: "<target> [file...]",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "identity",
						Aliases: []string{"i"},
						Usage:   "Path to age identity file",
						Sources: cli.EnvVars("OCIGE_IDENTITY"),
					},
					&cli.StringFlag{
						Name:    "output",
						Aliases: []string{"C"},
						Value:   ".",
						Usage:   "Destination directory",
					},
				},
				Action: handlePull,
			},
			{
				Name:      "ls",
				Usage:     "Lists files in the target",
				ArgsUsage: "<target>",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "identity",
						Aliases: []string{"i"},
						Usage:   "Path to age identity file",
						Sources: cli.EnvVars("OCIGE_IDENTITY"),
					},
				},
				Action: handleLs,
			},
			{
				Name:      "append",
				Usage:     "Adds files to an existing artifact",
				ArgsUsage: "<target> <file...>",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "identity",
						Aliases: []string{"i"},
						Usage:   "Path to age identity file",
						Sources: cli.EnvVars("OCIGE_IDENTITY"),
					},
					&cli.BoolFlag{
						Name:  "force",
						Usage: "Overwrite existing files without warning",
					},
				},
				Action: handleAppend,
			},
			{
				Name:      "rekey",
				Usage:     "Rotates the Vault Identity for a new recipients file",
				ArgsUsage: "<target> <new-recipients-file>",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "identity",
						Aliases: []string{"i"},
						Usage:   "Path to existing age identity file",
						Sources: cli.EnvVars("OCIGE_IDENTITY"),
					},
				},
				Action: handleRekey,
			},
			{
				Name:      "remove",
				Usage:     "Removes files from an artifact",
				ArgsUsage: "<target> <file...>",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "identity",
						Aliases: []string{"i"},
						Usage:   "Path to age identity file",
						Sources: cli.EnvVars("OCIGE_IDENTITY"),
					},
				},
				Action: handleRemove,
			},
			{
				Name:  "keygen",
				Usage: "Generates a new PQ-safe key pair",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "output",
						Aliases: []string{"o"},
						Usage:   "Output file (default: stdout)",
					},
				},
				Action: handleKeygen,
			},
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
