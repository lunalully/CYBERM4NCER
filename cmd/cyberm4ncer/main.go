// Command cyberm4ncer is the CYBERM4NCER CLI entry point.
package main

import (
	"os"

	"github.com/lunalully/cyberm4ncer/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
