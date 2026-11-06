package x

import "os/exec"

func run(ref string) { exec.Command("sh", "-c", "git log "+ref).Run() }
