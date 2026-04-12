package main

import (
	"context"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"
)

var version = "dev"

func main() {
	cmd := &cli.Command{
		Name:    "ocige",
		Version: version,
		Usage:   "Secure File Sharing over OCI Registries",
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
			&cli.IntFlag{
				Name:    "concurrency",
				Aliases: []string{"j"},
				Value:   5,
				Usage:   "Number of parallel jobs",
				Sources: cli.EnvVars("OCIGE_CONCURRENCY"),
			},
			&cli.BoolFlag{
				Name:    "silent",
				Aliases: []string{"s"},
				Usage:   "Disable progress visualization",
				Sources: cli.EnvVars("OCIGE_SILENT"),
			},
			&cli.IntFlag{
				Name:    "retries",
				Value:   2,
				Usage:   "Number of retries for failed network chunks",
				Sources: cli.EnvVars("OCIGE_RETRIES"),
			},
			&cli.BoolFlag{
				Name:  "allow-non-pq",
				Usage: "Allow using non-PQ-safe recipients (e.g. standard age keys)",
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
					&cli.StringFlag{
						Name:  "name",
						Usage: "Filename to use for stdin (-) or to rename a single file",
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
					&cli.StringFlag{
						Name:    "output",
						Aliases: []string{"o"},
						Usage:   "Output format (json, long, table)",
						Value:   "table",
					},
				},
				Action: handleLs,
			},
			{
				Name:      "cat",
				Usage:     "Outputs the decrypted content of a file to stdout",
				ArgsUsage: "<target> <file>",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "identity",
						Aliases: []string{"i"},
						Usage:   "Path to age identity file",
						Sources: cli.EnvVars("OCIGE_IDENTITY"),
					},
					&cli.BoolFlag{
						Name:    "force",
						Aliases: []string{"y"},
						Usage:   "Bypass terminal check for binary content",
					},
				},
				Action: handleCat,
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
					&cli.StringFlag{
						Name:  "name",
						Usage: "Filename to use for stdin (-) or to rename a single file",
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
				Name:      "delete",
				Usage:     "Deletes a manifest from the remote registry",
				ArgsUsage: "<target>",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "blobs",
						Usage: "Also delete all referenced blobs (config + layers)",
					},
				},
				Action: handleDelete,
			},
			{
				Name:      "mount",
				Usage:     "Mounts an OCI artifact as a read-only FUSE filesystem",
				ArgsUsage: "<target> <mountpoint>",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "identity",
						Aliases: []string{"i"},
						Usage:   "Path to age identity file",
						Sources: cli.EnvVars("OCIGE_IDENTITY"),
					},
					&cli.StringFlag{
						Name:    "cache-dir",
						Usage:   "Cache directory for encrypted chunks",
						Value:   defaultCacheDir(),
						Sources: cli.EnvVars("OCIGE_CACHE_DIR"),
					},
					&cli.IntFlag{
						Name:  "cache-size",
						Usage: "Maximum cache size in MB",
						Value: 1024,
					},
					&cli.BoolFlag{
						Name:  "allow-other",
						Usage: "Allow other users to access the mount",
					},
					&cli.BoolFlag{
						Name:  "debug",
						Usage: "Enable FUSE debug logging",
					},
				},
				Action: handleMount,
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
			{
				Name:  "cache",
				Usage: "Manage local chunk cache",
				Commands: []*cli.Command{
					{
						Name:      "cleanup",
						Usage:     "Removes cached chunks (global or per target)",
						ArgsUsage: "[target]",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:    "cache-dir",
								Usage:   "Cache directory for encrypted chunks",
								Value:   defaultCacheDir(),
								Sources: cli.EnvVars("OCIGE_CACHE_DIR"),
							},
							&cli.BoolFlag{
								Name:  "insecure",
								Usage: "Use plain HTTP for registry",
							},
						},
						Action: handleCacheCleanup,
					},
				},
			},
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
