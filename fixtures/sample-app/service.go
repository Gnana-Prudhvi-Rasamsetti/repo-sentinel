package sample

import (
	"crypto/tls"
	"os/exec"
)

func run(input string) {
	clientTLS := &tls.Config{InsecureSkipVerify: true}
	_ = clientTLS
	_ = exec.Command("sh", "-c", input)
}
