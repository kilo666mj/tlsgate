package main

import (
	"log"
	"net"
	"os"
	"strconv"
)

// notifyReady tells systemd (Type=notify units) that this process is up and
// serving. It includes MAINPID because after a tableflip upgrade the process
// that ends up serving is a child of the original main PID; systemd must be
// told to track the new PID or it will keep watching the departing parent.
//
// This requires NotifyAccess=all in the unit, since the notification arrives
// from a process systemd does not yet consider the main one. It is a no-op when
// NOTIFY_SOCKET is unset (i.e. not running under systemd).
func notifyReady() {
	sdNotify("READY=1\nMAINPID=" + strconv.Itoa(os.Getpid()))
}

func sdNotify(state string) {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return
	}
	// systemd uses a leading '@' to denote an abstract-namespace socket, which
	// is represented to the kernel as a leading NUL byte.
	if socket[0] == '@' {
		socket = "\x00" + socket[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		log.Printf("sd_notify: %v", err)
		return
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(state)); err != nil {
		log.Printf("sd_notify: %v", err)
	}
}
