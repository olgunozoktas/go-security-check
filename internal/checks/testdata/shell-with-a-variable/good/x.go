package x

import "os/exec"

func run(ref string) {
	exec.Command("git", "log", ref).Run()
	exec.Command("sh", "-c", "make build").Run()
}
