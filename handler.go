package main

import (
	"fmt"
	"math/rand"
	"net"
	"time"
	go_docker "github.com/fsouza/go-dockerclient"
)

type VoidResponse struct{}

type Docker struct{
	client *go_docker.Client
}


func GenerateMac() (net.HardwareAddr) {
	buf := make([]byte, 6)
	var mac net.HardwareAddr

	_, err  := rand.Read(buf)
	if err != nil {}

	// Set the local bit
	buf[0] |= 2

	mac = append(mac, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5])

	return mac
}


func generateVethName() string {
	n := 6
	rand.Seed(time.Now().UnixNano())
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return fmt.Sprintf("veth-%s", string(b))
}

// GetVMContainer returns the underlying docker container object for a
// given VM
func (d *Docker) GetContainerInfo (endpointID string) (*go_docker.Container, error) {
	containers, err := d.client.ListContainers(go_docker.ListContainersOptions{
		Filters: map[string][]string{
			"name": {
				endpointID,
			},
		},
	})

	if err != nil {
		return nil, err
	}

	// no such container
	if len(containers) == 0 {
		return nil, nil
	}

	return d.client.InspectContainer(containers[0].ID)
}
