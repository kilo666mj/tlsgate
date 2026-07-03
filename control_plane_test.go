package main

import (
	"fmt"
	"testing"
	"time"
)

func TestTLSObservationLimitsIPAndPortLists(t *testing.T) {
	ips := make([]string, maxControlPlaneObservationValues+5)
	ports := make([]int, maxControlPlaneObservationValues+5)
	for i := range ips {
		ips[i] = fmt.Sprintf("192.0.2.%d", i%255)
		ports[i] = 1000 + i
	}
	entry := Entry{
		Status:    StatusPending,
		FirstSeen: time.Unix(1, 0),
		LastSeen:  time.Unix(2, 0),
		IPs:       ips,
		Ports:     ports,
		Count:     10,
	}

	obs := tlsObservation("fp", entry)
	if len(obs.IPs) != maxControlPlaneObservationValues {
		t.Fatalf("len(obs.IPs) = %d, want %d", len(obs.IPs), maxControlPlaneObservationValues)
	}
	if len(obs.Ports) != maxControlPlaneObservationValues {
		t.Fatalf("len(obs.Ports) = %d, want %d", len(obs.Ports), maxControlPlaneObservationValues)
	}
	if len(entry.IPs) != maxControlPlaneObservationValues+5 {
		t.Fatalf("tlsObservation mutated entry IPs")
	}
	if obs.IPs[0] != ips[0] || obs.IPs[len(obs.IPs)-1] != ips[maxControlPlaneObservationValues-1] {
		t.Fatalf("observation IPs were not truncated in order")
	}
	if obs.Ports[0] != ports[0] || obs.Ports[len(obs.Ports)-1] != ports[maxControlPlaneObservationValues-1] {
		t.Fatalf("observation ports were not truncated in order")
	}
}
