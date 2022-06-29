//
// Copyright (c) 2017,2022 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package main

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/01org/ciao/uuid"
	bolt "go.etcd.io/bbolt"
	"github.com/moby/libnetwork/drivers/remote/api"
	ipamapi "github.com/docker/libnetwork/ipams/remote/api"
	goipam "github.com/metal-stack/go-ipam"
	"github.com/golang/glog"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

type epVal struct {
	IP             string
	mask           string
	vethClientName string
	vethServerName string
	vethClientIf   int
	vethServerIf   int
	vethClientMac  net.HardwareAddr
	vethServerMac  net.HardwareAddr
}

type nwVal struct {
	Bridge  string //The bridge on which the ports will be created
	Gateway net.IPNet
	Pipeline int
	actionCount int
	EndpointID string
}

type ipamVal struct {
	subnet        string
	gateway       string
}

var epMap struct {
	sync.Mutex
	m map[string]*epVal
}

var nwMap struct {
	sync.Mutex
	Pipeline int // The P4 pipeline used
	m map[string]*nwVal
}

var brMap struct {
	sync.Mutex
	brCount int
	m       map[string]int
}

var ipamMap struct {
	sync.Mutex
	count int
	m     map[string]*ipamVal
}

var dbFile string
var db *bolt.DB
var nsID netns.NsHandle
var ipdkMutex sync.Mutex
var ipdkIpam goipam.Ipamer
var hostPorts *bool

const switchNS = "switch"

func init() {
	epMap.m = make(map[string]*epVal)
	nwMap.m = make(map[string]*nwVal)
	brMap.m = make(map[string]int)
	ipamMap.m = make(map[string]*ipamVal)
	brMap.brCount = 1
	nwMap.Pipeline = 1
	ipamMap.count = 0
	dbFile = "/tmp/dpdk_bolt.db"
}

//We should never see any errors in this function
func sendResponse(resp interface{}, w http.ResponseWriter) {
	rb, err := json.Marshal(resp)
	if err != nil {
		glog.Errorf("unable to marshal response %v", err)
	}
	glog.Infof("Sending response := %v, %v", resp, err)
	fmt.Fprintf(w, "%s", rb)
	return
}

func getBody(r *http.Request) ([]byte, error) {
	body, err := ioutil.ReadAll(r.Body)
	glog.Infof("URL [%s] Body [%s] Error [%v]", r.URL.Path[1:], string(body), err)
	return body, err
}

func handler(w http.ResponseWriter, r *http.Request) {
	body, _ := getBody(r)
	resp := api.Response{}
	resp.Err = "Unhandled API request " + string(r.URL.Path[1:]) + " " + string(body)
	sendResponse(resp, w)
}

func handlerPluginActivate(w http.ResponseWriter, r *http.Request) {
	_, _ = getBody(r)
	//TODO: Where is this encoding?
	resp := `{
    "Implements": ["NetworkDriver", "IpamDriver"]
}`
	fmt.Fprintf(w, "%s", resp)
}

func handlerGetCapabilities(w http.ResponseWriter, r *http.Request) {
	_, _ = getBody(r)
	resp := api.GetCapabilityResponse{Scope: "local"}
	sendResponse(resp, w)
}

func createIpdkNetworkHostPort(gwString string, nm *nwVal) error {
	glog.Infof("About to lock epMap")
	epMap.Lock()
	defer epMap.Unlock()
	glog.Infof("Locked epMap")

	ipString := strings.Split(gwString, "/")
	ipAddr, err := netlink.ParseAddr(gwString)
	if err != nil {
		glog.Info("ERROR: Failed parsing IP address [%v]", err)
		return err
	}

	// Create a unique name and host
	vethServer := generateVethName()
	vethClient := generateVethName()

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: vethClient,
			HardwareAddr: GenerateMac(),
		},
		PeerName: 		vethServer,
		PeerNamespace:		nsID,
		PeerHardwareAddr: 	GenerateMac(),
	}

	if err := netlink.LinkAdd(veth); err != nil {
		glog.Infof("ERROR: Cannot add veth device [%v] ", err)
		return err
	}

	glog.Infof("Adding veth pair (%s/%s) with nsID %d and MAC %s", vethServer, vethClient, veth.PeerNamespace, veth.PeerHardwareAddr)

	l, err := netlink.LinkByName(vethServer)
	if err != nil{
		glog.Infof("ERROR: Error getting veth server [%v] ", err)
		return err
	}
	if l == nil {
		glog.Infof("ERROR: Cannot find veth server [%v] ", err)
		return err
	}
	vethServerMac := l.Attrs().HardwareAddr
	glog.Infof("INFO: vethServerMac is %s", vethServerMac.String())
	vethServerIf := l.Attrs().Index
	if err = netlink.LinkSetNsFd(l, int(nsID)); err != nil {
		glog.Infof("ERROR: Cannot set veth server interface up [%v]", err)
		return err
	}

	// Set the link up in the namespace
	var ch *netlink.Handle

	nh, nerr := netns.GetFromName(switchNS)
	if nerr != nil {
		glog.Infof("ERROR: Cannot get handle to %s namespace [%v]", switchNS, err)
		return err
	}
	ch, err = netlink.NewHandleAt(nh)
	if err != nil {
		glog.Infof("ERROR: Cannot get handle for namespace [%v]", err)
		return err
	}
	l, err = ch.LinkByName(vethServer)
	if err != nil{
		glog.Infof("ERROR: Error getting dummy device %s [%v]", vethServer, err)
		return err
	}
	if l == nil {
		glog.Infof("ERROR: Cannot find dummy device %s [%v]", vethServer, err)
		return err
	}

	if err = ch.LinkSetUp(l); err != nil {
		glog.Infof("ERROR: Cannot set veth server interface up [%v] ", err)
		return err
	}

	l, err = netlink.LinkByName(vethClient)
	if err != nil{
		glog.Infof("ERROR: Error getting veth client [%v] ", err)
		return err
	}
	if l == nil {
		glog.Infof("ERROR: Cannot find veth client [%v] ", err)
		return err
	}

	// Add the IP address to the interface
	err = netlink.AddrAdd(l, ipAddr)
	if (err != nil) {
		glog.Infof("ERROR: Cannot add IP [%s] to interface: [%v]", ipString, err)
		return err
	}

	if err = netlink.LinkSetUp(l); err != nil {
		glog.Infof("ERROR: Cannot set veth client interface up [%v] ", err)
		return err
	}

	l, err = netlink.LinkByName(vethClient)
	if err != nil{
		glog.Infof("ERROR: Error getting veth client [%v] ", err)
		return err
	}
	if l == nil {
		glog.Infof("ERROR: Cannot find veth client [%v] ", err)
		return err
	}

	vethClientMac := l.Attrs().HardwareAddr
	glog.Infof("INFO: vethClientMac is %s", vethClientMac.String())
	vethClientIf := l.Attrs().Index

	epMap.m[nm.EndpointID] = &epVal{
		IP:            ipString[0],
		mask:          ipString[1],
		vethServerName: vethServer,
		vethClientName: vethClient,
		vethClientMac: vethClientMac,
		vethServerMac: vethServerMac,
		vethClientIf: vethClientIf,
		vethServerIf: vethServerIf,
	}

	if err := dbAdd("epMap", nm.EndpointID, epMap.m[nm.EndpointID]); err != nil {
		glog.Errorf("Unable to update db %v %v", err, ipString[0])
	}

	// Plumb into ipdk container
	cmd := "docker"
	args := []string{"exec", "ipdk", "psabpf-ctl", "add-port", "pipe", fmt.Sprintf("%d", nm.Pipeline), "dev", fmt.Sprintf("%s", vethServer)}
	glog.Infof("INFO: Running command [%v] with args [%v]", cmd, args)
	if err := exec.Command(cmd, args...).Run(); err != nil {
		glog.Infof("ERROR: [%v] [%v] [%v]", cmd, args, err)
		return err
	}

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd2 := exec.Command("docker", "exec", "ipdk", "psabpf-ctl", "action-selector", "add-member", "pipe", fmt.Sprintf("%d", nm.Pipeline), "DemoIngress_as", "action", "id", "1", "data",
		fmt.Sprintf("%d", vethServerIf), fmt.Sprintf("%s", vethServerMac.String()), fmt.Sprintf("%s", vethClientMac.String()))
	cmd2.Stdout = &out
	cmd2.Stderr = &stderr
	glog.Infof("INFO: Running command [%v] with args [%v]", cmd2, args)
	if err = cmd2.Run(); err != nil {
		fmt.Println(fmt.Sprint(err) + ": " + stderr.String())
		glog.Infof("ERROR: [%v] [%v] [%v]", cmd2, args, err)
		return err
	}

	// Bump actionCount
	routingAction := nm.actionCount
	nm.actionCount = nm.actionCount + 1

	cmd3 := exec.Command("docker", "exec", "ipdk", "psabpf-ctl", "table", "add", "pipe", fmt.Sprintf("%d", nm.Pipeline), "DemoIngress_tbl_routing", "ref", "key",
		fmt.Sprintf("%s/32", ipString[0]), "data", fmt.Sprintf("%d", routingAction))
	cmd3.Stdout = &out
	cmd3.Stderr = &stderr
	glog.Infof("INFO: Running command [%v] with args [%v]", cmd3, args)
	if err = cmd3.Run(); err != nil {
		fmt.Println(fmt.Sprint(err) + ": " + stderr.String())
		glog.Infof("ERROR: [%v] [%v] [%v]", cmd3, args, err)
                return err
	}

	cmd4 := exec.Command("docker", "exec", "ipdk", "psabpf-ctl", "table", "add", "pipe", fmt.Sprintf("%d", nm.Pipeline), "DemoIngress_tbl_arp_ipv4", "action", "id", "2", "key",
		fmt.Sprintf("%d", vethServerIf), "1", fmt.Sprintf("%s/%s", ipString[0], ipString[1]), "data", fmt.Sprintf("%s", vethServerMac.String()))
	cmd4.Stdout = &out
	cmd4.Stderr = &stderr
	glog.Infof("INFO: Running command [%v] with args [%v]", cmd4, args)
	if err = cmd4.Run(); err != nil {
		fmt.Println(fmt.Sprint(err) + ": " + stderr.String())
		glog.Infof("ERROR: [%v] [%v] [%v]", cmd4, args, err)
                return err
	}

	return nil
}

func deleteIpdkNetworkHostPort(nm *nwVal) error {
	glog.Infof("About to lock epMap")
	epMap.Lock()
	defer epMap.Unlock()
	glog.Infof("Locked epMap")
	em := epMap.m[nm.EndpointID]

	// Delete the GW veth pair
	cmd := "docker"
	args := []string{"exec", "ipdk", "psabpf-ctl", "table", "delete", "pipe", fmt.Sprintf("%d", nm.Pipeline), "DemoIngress_tbl_arp_ipv4", "key",
		fmt.Sprintf("%d", em.vethServerIf), "1", fmt.Sprintf("%s/%s", em.IP, em.mask)}
	glog.Infof("INFO: Running command [%v] with args [%v]", cmd, args)
	if err := exec.Command(cmd, args...).Run(); err != nil {
		glog.Infof("ERROR: [%v] [%v] [%v]", cmd, args, err)
		return err
	}

	args = []string{"exec", "ipdk", "psabpf-ctl", "table", "delete", "pipe", fmt.Sprintf("%d", nm.Pipeline), "DemoIngress_tbl_routing", "key", fmt.Sprintf("%s/32", em.IP)}
	glog.Infof("INFO: Running command [%v] with args [%v]", cmd, args)
	if err := exec.Command(cmd, args...).Run(); err != nil {
		glog.Infof("ERROR: [%v] [%v] [%v]", cmd, args, err)
                return err
        }

	args = []string{"exec", "ipdk", "psabpf-ctl", "del-port", "pipe", fmt.Sprintf("%d", nm.Pipeline), "dev", fmt.Sprintf("%s", em.vethServerName)}
	glog.Infof("INFO: Running command [%v] with args [%v]", cmd, args)
	if err := exec.Command(cmd, args...).Run(); err != nil {
		glog.Infof("ERROR: [%v] [%v] [%v]", cmd, args, err)
		return err
	}

	// Now, cleanup the veth interfaces
	l, err := netlink.LinkByName(em.vethClientName)
	if err != nil{
		glog.Infof("ERROR: Error getting veth server [%v] ", err)
		return err
	}
	if l == nil {
		glog.Infof("ERROR: Cannot find veth server [%v] ", err)
		return err
	}

	err = netlink.LinkSetDown(l)
	if err != nil {
		return err
	}

	err = netlink.LinkDel(l)
	if err != nil {
		return err
	}

	delete(epMap.m, nm.EndpointID)
	if err := dbDelete("epMap", nm.EndpointID); err != nil {
		glog.Errorf("Unable to update db %v %v", err, em)
	}

	return nil
}

func handlerCreateNetwork(w http.ResponseWriter, r *http.Request) {
	resp := api.CreateNetworkResponse{}
	bridge := "br"

	body, err := getBody(r)
	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := api.CreateNetworkRequest{}
	if err := json.Unmarshal(body, &req); err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	nwMap.Lock()
	defer nwMap.Unlock()

	// Save pipeline ID
	pipeline := nwMap.Pipeline
	nwMap.Pipeline = nwMap.Pipeline + 1

	// Create Endpoint ID
	id := uuid.Generate().String()

	//Record the docker network UUID to SDN bridge mapping
	//This has to survive a plugin crash/restart and needs to be persisted
	nwMap.m[req.NetworkID] = &nwVal{
		Bridge:  bridge,
		Gateway: *req.IPv4Data[0].Gateway,
		Pipeline: pipeline,
		actionCount: 1,
		EndpointID: id,
	}

	if err := dbAdd("nwMap", req.NetworkID, nwMap.m[req.NetworkID]); err != nil {
		glog.Errorf("Unable to update db %v", err)
	}

	// For IPDK, we are connecting endpoints via a bridge which requires
	// a unique integer ID.
	brMap.Lock()
	defer brMap.Unlock()
	brMap.m[req.NetworkID] = brMap.brCount
	brMap.brCount = brMap.brCount + 1
	if err := dbAdd("brMap", req.NetworkID, brMap.m[req.NetworkID]); err != nil {
		glog.Errorf("Unable to update db %v", err)
	}

	// .FIXME: Need to stop hard coding demo.o below
	cmd := "docker"
	args := []string{"exec", "ipdk", "psabpf-ctl", "pipeline", "load", "id", fmt.Sprintf("%d", pipeline), "/root/ipdk-ebpf/demo.o"}
	glog.Infof("INFO: Running command [%v] with args [%v]", cmd, args)
	if err := exec.Command(cmd, args...).Run(); err != nil {
		glog.Infof("ERROR: [%v] [%v] [%v]", cmd, args, err)
		resp.Err= fmt.Sprintf("Error EndPointCreate: [%v] [%v] [%v]", cmd, args, err)
		sendResponse(resp, w)
		return
	}

	if *hostPorts {
		err = createIpdkNetworkHostPort(req.IPv4Data[0].Gateway.String(), nwMap.m[req.NetworkID])
		if err != nil {
			glog.Errorf("ERROR: Unable to add host port port: [%v]", err)
			resp.Err = "Error: " + err.Error()
			sendResponse(resp, w)
			return
		}
	}

	sendResponse(resp, w)
}

func handlerDeleteNetwork(w http.ResponseWriter, r *http.Request) {
	resp := api.DeleteNetworkResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := api.DeleteNetworkRequest{}
	if err = json.Unmarshal(body, &req); err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	if *hostPorts {
		err = deleteIpdkNetworkHostPort(nwMap.m[req.NetworkID])
		if err != nil {
			glog.Errorf("ERROR: Unable to add gateway port: [%v]", err)
			resp.Err = "Error: " + err.Error()
			sendResponse(resp, w)
			return
		}
	}

	glog.Infof("Delete Network := %v", req.NetworkID)

	nwMap.Lock()
	defer nwMap.Unlock()

	bridge := nwMap.m[req.NetworkID].Bridge
	pipeline := nwMap.m[req.NetworkID].Pipeline
	delete(nwMap.m, req.NetworkID)
	if err := dbDelete("nwMap", req.NetworkID); err != nil {
		glog.Errorf("Unable to update db %v %v", err, bridge)
	}

	brMap.Lock()
	defer brMap.Unlock()
	delete(brMap.m, req.NetworkID)
	if err := dbDelete("brMap", req.NetworkID); err != nil {
		glog.Errorf("Unable to update db %v %v", err, bridge)
	}

	cmd := "docker"
	args := []string{"exec", "ipdk", "psabpf-ctl", "pipeline", "unload", "id", fmt.Sprintf("%d", pipeline)}
	glog.Infof("INFO: Running command [%v] with args [%v]", cmd, args)
	if err := exec.Command(cmd, args...).Run(); err != nil {
		glog.Infof("ERROR: [%v] [%v] [%v]", cmd, args, err)
		resp.Err= fmt.Sprintf("Error EndPointCreate: [%v] [%v] [%v]", cmd, args, err)
		sendResponse(resp, w)
		return
	}

	sendResponse(resp, w)
	return
}

func handlerEndpointOperInfof(w http.ResponseWriter, r *http.Request) {
	resp := api.EndpointInfoResponse{}
	body, err := getBody(r)

	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := api.EndpointInfoRequest{}
	err = json.Unmarshal(body, &req)

	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	sendResponse(resp, w)
}

func handlerCreateEndpoint(w http.ResponseWriter, r *http.Request) {
	resp := api.CreateEndpointResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := api.CreateEndpointRequest{}
	if err = json.Unmarshal(body, &req); err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	if req.Interface.Address == "" {
		resp.Err = "Error: IP Address parameter not provided in docker run"
		sendResponse(resp, w)
		return
	}

	ip, _, err := net.ParseCIDR(req.Interface.Address)
	if err != nil {
		resp.Err = "Error: Invalid IP Address " + err.Error()
		sendResponse(resp, w)
		return
	}

	glog.Infof("About to lock nwMap")
	nwMap.Lock()
	defer nwMap.Unlock()
	glog.Infof("Locked nwMap")

	glog.Infof("About to lock epMap")
	epMap.Lock()
	defer epMap.Unlock()
	glog.Infof("Locked epMap")

	bridge := nwMap.m[req.NetworkID].Bridge
	if bridge == "" {
		resp.Err = "Error: incompatible network"
		sendResponse(resp, w)
		return
	}

	// Create a unique name and host
	vethServer := generateVethName()
	vethClient := generateVethName()

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: vethClient,
			HardwareAddr: GenerateMac(),
		},
		PeerName: 		vethServer,
		PeerNamespace:		nsID,
		PeerHardwareAddr: 	GenerateMac(),
	}


	glog.Infof("Adding veth pair (%s/%s) with nsID %d and MAC %s", vethServer, vethClient, veth.PeerNamespace, veth.PeerHardwareAddr)

	if err := netlink.LinkAdd(veth); err != nil {
		glog.Infof("ERROR: Cannot add veth device [%v] ", err)
		resp.Err = fmt.Sprintf("Error creating veth: [%v]", err)
		sendResponse(resp, w)
		return
	}

	l, err := netlink.LinkByName(vethClient)
	if err != nil{
		glog.Infof("ERROR: Error getting veth client [%v] ", err)
		resp.Err = fmt.Sprintf("Error getting veth client: [%v]", err)
		sendResponse(resp, w)
		return
	}
        if l == nil {
		glog.Infof("ERROR: Cannot find veth client [%v] ", err)
		resp.Err = fmt.Sprintf("Cannot find veth client : [%v]", err)
		sendResponse(resp, w)
		return
        }
	var vethClientMac net.HardwareAddr

	if req.Interface.MacAddress != ""  {
		vethClientMacString := req.Interface.MacAddress
		vethClientMac, _ = net.ParseMAC(vethClientMacString)
	} else {
		vethClientMac = l.Attrs().HardwareAddr
	}
	glog.Infof("INFO: vethClientMac is %s", vethClientMac.String())
	vethClientIf := l.Attrs().Index
	if err = netlink.LinkSetUp(l); err != nil {
		glog.Infof("ERROR: Cannot set veth client interface up [%v] ", err)
		resp.Err = fmt.Sprintf("Cannot set veth client interface up : [%v]", err)
		sendResponse(resp, w)
		return
	}

	l, err = netlink.LinkByName(vethServer)
	if err != nil{
		glog.Infof("ERROR: Error getting veth server [%v] ", err)
		resp.Err = fmt.Sprintf("Error getting veth server: [%v]", err)
		sendResponse(resp, w)
		return
	}
        if l == nil {
		glog.Infof("ERROR: Cannot find veth server [%v] ", err)
		resp.Err = fmt.Sprintf("Cannot find veth server : [%v]", err)
		sendResponse(resp, w)
		return
        }
	vethServerMac := l.Attrs().HardwareAddr
	vethServerIf := l.Attrs().Index
	if err = netlink.LinkSetNsFd(l, int(nsID)); err != nil {
		glog.Infof("ERROR: Cannot set veth server interface up [%v]", err)
		resp.Err = fmt.Sprintf("Cannot set veth server interface up : [%v]", err)
		sendResponse(resp, w)
		return
	}

	// Set the link up in the namespace
	var ch *netlink.Handle

	nh, nerr := netns.GetFromName(switchNS)
	if nerr != nil {
		glog.Infof("ERROR: Cannot get handle to %s namespace [%v]", switchNS, err)
		resp.Err = fmt.Sprintf("Cannot get handle to %s namespace : [%v]", switchNS, err)
		sendResponse(resp, w)
		return
	}
	ch, err = netlink.NewHandleAt(nh)
	if err != nil {
		glog.Infof("ERROR: Cannot get handle for namespace [%v]", err)
		resp.Err = fmt.Sprintf("Cannot get handle for s namespace : [%v]", err)
		sendResponse(resp, w)
		return
	}
	l, err = ch.LinkByName(vethServer)
	if err != nil{
		glog.Infof("ERROR: Error getting dummy device %s [%v]", vethServer, err)
		resp.Err = fmt.Sprintf(":Error getting dummy device %s [%v]", vethServer, err)
		sendResponse(resp, w)
		return
	}
	if l == nil {
		glog.Infof("ERROR: Cannot find dummy device %s [%v]", vethServer, err)
		resp.Err = fmt.Sprintf("Cannot find dummy device %s [%v]", vethServer, err)
		sendResponse(resp, w)
		return
	}

	if err = ch.LinkSetUp(l); err != nil {
		glog.Infof("ERROR: Cannot set veth server interface up [%v] ", err)
		resp.Err = fmt.Sprintf("Cannot set veth server interface up : [%v]", err)
		sendResponse(resp, w)
		return
	}

	ipString := strings.Split(req.Interface.Address, "/")

	epMap.m[req.EndpointID] = &epVal{
		IP:            ipString[0],
		mask:          ipString[1],
		vethServerName: vethServer,
		vethClientName: vethClient,
		vethClientMac: vethClientMac,
		vethServerMac: vethServerMac,
		vethClientIf: vethClientIf,
		vethServerIf: vethServerIf,
	}

	if err := dbAdd("epMap", req.EndpointID, epMap.m[req.EndpointID]); err != nil {
		glog.Errorf("Unable to update db %v %v", err, ip)
	}

	sendResponse(resp, w)
}

func handlerDeleteEndpoint(w http.ResponseWriter, r *http.Request) {
	resp := api.DeleteEndpointResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := api.DeleteEndpointRequest{}
	if err = json.Unmarshal(body, &req); err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	epMap.Lock()
	nwMap.Lock()
	defer nwMap.Unlock()
	defer epMap.Unlock()

	m := epMap.m[req.EndpointID]

	// Delete veth devices
	l, err := netlink.LinkByName(m.vethClientName)
	if err != nil{
		glog.Infof("ERROR: Error getting veth server [%v] ", err)
		resp.Err = fmt.Sprintf("Error getting veth server: [%v]", err)
		sendResponse(resp, w)
		return
	}
        if l == nil {
		glog.Infof("ERROR: Cannot find veth server [%v] ", err)
		resp.Err = fmt.Sprintf("Cannot find veth server : [%v]", err)
		sendResponse(resp, w)
		return
        }

	err = netlink.LinkSetDown(l)
	if err != nil {
		resp.Err = "Error: cannot set link " + m.vethClientName + " down" + err.Error()
		sendResponse(resp, w)
		return
	}

	err = netlink.LinkDel(l)
	if err != nil {
		resp.Err = "Error: cannot delete link " + m.vethClientName + " down" + err.Error()
		sendResponse(resp, w)
		return
	}

	delete(epMap.m, req.EndpointID)
	if err := dbDelete("epMap", req.EndpointID); err != nil {
		glog.Errorf("Unable to update db %v %v", err, m)
	}

	sendResponse(resp, w)
}

func handlerJoin(w http.ResponseWriter, r *http.Request) {
	resp := api.JoinResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := api.JoinRequest{}
	if err := json.Unmarshal(body, &req); err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	brMap.Lock()
	defer brMap.Unlock()

	nwMap.Lock()
	defer nwMap.Unlock()
	epMap.Lock()
	defer epMap.Unlock()
	nm := nwMap.m[req.NetworkID]
	em := epMap.m[req.EndpointID]

	// Here we want to do the following:
	// 0. psabpf-ctl add-port pipe 1 dev eth0
	// 1. psabpf-ctl action-selector add_member pipe "$PIPELINE" DemoIngress_as id 1 data "$SWITCH_SERVER1_PORT_ID" "$SWITCH_SERVER1_PORT_MAC" "$SERVER1_MAC"
	// 2. psabpf-ctl table add pipe "$PIPELINE" DemoIngress_tbl_routing ref key "$SERVER1_IP/32" data 1
	// 3. psabpf-ctl table add pipe "$PIPELINE" DemoIngress_tbl_arp_ipv4 id 2 key "$SWITCH_SERVER1_PORT_ID" 1 "$SERVER1_IP/$SERVER1_IP_PREFIX" data "$SWITCH_SERVER1_PORT_MAC"
	cmd := "docker"
	args := []string{"exec", "ipdk", "psabpf-ctl", "add-port", "pipe", fmt.Sprintf("%d", nm.Pipeline), "dev", fmt.Sprintf("%s", em.vethServerName)}
	glog.Infof("INFO: Running command [%v] with args [%v]", cmd, args)
	if err := exec.Command(cmd, args...).Run(); err != nil {
		glog.Infof("ERROR: [%v] [%v] [%v]", cmd, args, err)
		resp.Err= fmt.Sprintf("Error EndPointCreate: [%v] [%v] [%v]", cmd, args, err)
		sendResponse(resp, w)
		return
	}

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd2 := exec.Command("docker", "exec", "ipdk", "psabpf-ctl", "action-selector", "add-member", "pipe", fmt.Sprintf("%d", nm.Pipeline), "DemoIngress_as", "action", "id", "1", "data",
		fmt.Sprintf("%d", em.vethServerIf), fmt.Sprintf("%s", em.vethServerMac.String()), fmt.Sprintf("%s", em.vethClientMac.String()))
	cmd2.Stdout = &out
	cmd2.Stderr = &stderr
	glog.Infof("INFO: Running command [%v] with args [%v]", cmd2, args)
	if err = cmd2.Run(); err != nil {
		fmt.Println(fmt.Sprint(err) + ": " + stderr.String())
		glog.Infof("ERROR: [%v] [%v] [%v]", cmd2, args, err)
		resp.Err= fmt.Sprintf("Error EndPointCreate: [%v] [%v] [%v]", cmd2, args, err)
		sendResponse(resp, w)
		return
	}

	// Bump actionCount
	routingAction := nm.actionCount
	nm.actionCount = nm.actionCount + 1

	cmd3 := exec.Command("docker", "exec", "ipdk", "psabpf-ctl", "table", "add", "pipe", fmt.Sprintf("%d", nm.Pipeline), "DemoIngress_tbl_routing", "ref", "key",
		fmt.Sprintf("%s/32", em.IP), "data", fmt.Sprintf("%d", routingAction))
	cmd3.Stdout = &out
	cmd3.Stderr = &stderr
	glog.Infof("INFO: Running command [%v] with args [%v]", cmd3, args)
	if err = cmd3.Run(); err != nil {
		fmt.Println(fmt.Sprint(err) + ": " + stderr.String())
		glog.Infof("ERROR: [%v] [%v] [%v]", cmd3, args, err)
		resp.Err= fmt.Sprintf("Error EndPointCreate: [%v] [%v] [%v]", cmd3, args, err)
		sendResponse(resp, w)
		return
	}

	cmd4 := exec.Command("docker", "exec", "ipdk", "psabpf-ctl", "table", "add", "pipe", fmt.Sprintf("%d", nm.Pipeline), "DemoIngress_tbl_arp_ipv4", "action", "id", "2", "key",
		fmt.Sprintf("%d", em.vethServerIf), "1", fmt.Sprintf("%s/%s", em.IP, em.mask), "data", fmt.Sprintf("%s", em.vethServerMac.String()))
	cmd4.Stdout = &out
	cmd4.Stderr = &stderr
	glog.Infof("INFO: Running command [%v] with args [%v]", cmd4, args)
	if err = cmd4.Run(); err != nil {
		fmt.Println(fmt.Sprint(err) + ": " + stderr.String())
		glog.Infof("ERROR: [%v] [%v] [%v]", cmd4, args, err)
		resp.Err= fmt.Sprintf("Error EndPointCreate: [%v] [%v] [%v]", cmd4, args, err)
		sendResponse(resp, w)
		return
	}

	resp.Gateway = nm.Gateway.IP.String()
	resp.InterfaceName = &api.InterfaceName{
		SrcName:   em.vethClientName,
		DstPrefix: "eth",
	}
	glog.Infof("Join Response %v %v", resp, em.vethClientName)
	sendResponse(resp, w)
}

func handlerLeave(w http.ResponseWriter, r *http.Request) {
	resp := api.LeaveResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := api.LeaveRequest{}
	if err := json.Unmarshal(body, &req); err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	nwMap.Lock()
	defer nwMap.Unlock()
	epMap.Lock()
	defer epMap.Unlock()
	nm := nwMap.m[req.NetworkID]
	em := epMap.m[req.EndpointID]

	cmd := "docker"
	args := []string{"exec", "ipdk", "psabpf-ctl", "table", "delete", "pipe", fmt.Sprintf("%d", nm.Pipeline), "DemoIngress_tbl_arp_ipv4", "key",
		fmt.Sprintf("%d", em.vethServerIf), "1", fmt.Sprintf("%s/%s", em.IP, em.mask)}
	glog.Infof("INFO: Running command [%v] with args [%v]", cmd, args)
	if err := exec.Command(cmd, args...).Run(); err != nil {
		glog.Infof("ERROR: [%v] [%v] [%v]", cmd, args, err)
		resp.Err= fmt.Sprintf("Error EndPointCreate: [%v] [%v] [%v]", cmd, args, err)
		sendResponse(resp, w)
		return
	}

	args = []string{"exec", "ipdk", "psabpf-ctl", "table", "delete", "pipe", fmt.Sprintf("%d", nm.Pipeline), "DemoIngress_tbl_routing", "key", fmt.Sprintf("%s/32", em.IP)}
	glog.Infof("INFO: Running command [%v] with args [%v]", cmd, args)
	if err = exec.Command(cmd, args...).Run(); err != nil {
		glog.Infof("ERROR: [%v] [%v] [%v]", cmd, args, err)
		resp.Err= fmt.Sprintf("Error EndPointCreate: [%v] [%v] [%v]", cmd, args, err)
		sendResponse(resp, w)
		return
	}

	args = []string{"exec", "ipdk", "psabpf-ctl", "del-port", "pipe", fmt.Sprintf("%d", nm.Pipeline), "dev", fmt.Sprintf("%s", em.vethServerName)}
	glog.Infof("INFO: Running command [%v] with args [%v]", cmd, args)
	if err = exec.Command(cmd, args...).Run(); err != nil {
		glog.Infof("ERROR: [%v] [%v] [%v]", cmd, args, err)
		resp.Err= fmt.Sprintf("Error EndPointCreate: [%v] [%v] [%v]", cmd, args, err)
		sendResponse(resp, w)
		return
	}

	sendResponse(resp, w)
}

func handlerDiscoverNew(w http.ResponseWriter, r *http.Request) {
	resp := api.DiscoveryResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := api.DiscoveryNotification{}
	if err := json.Unmarshal(body, &req); err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	sendResponse(resp, w)
}

func handlerDiscoverDelete(w http.ResponseWriter, r *http.Request) {
	resp := api.DiscoveryResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := api.DiscoveryNotification{}
	if err := json.Unmarshal(body, &req); err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	sendResponse(resp, w)
}

func handlerExternalConnectivity(w http.ResponseWriter, r *http.Request) {
	resp := api.Response{}

	sendResponse(resp, w)

}

func handlerRevokeExternalConnectivity(w http.ResponseWriter, r *http.Request) {
	resp := api.Response{}

	sendResponse(resp, w)
}

func ipamGetCapabilities(w http.ResponseWriter, r *http.Request) {
	if _, err := getBody(r); err != nil {
		glog.Infof("ipamGetCapabilities: unable to get request body [%v]", err)
	}
	resp := ipamapi.GetCapabilityResponse{RequiresMACAddress: true}
	sendResponse(resp, w)
}

func ipamGetDefaultAddressSpaces(w http.ResponseWriter, r *http.Request) {
	resp := ipamapi.GetAddressSpacesResponse{}
	if _, err := getBody(r); err != nil {
		glog.Infof("ipamGetDefaultAddressSpaces: unable to get request body [%v]", err)
	}

	resp.GlobalDefaultAddressSpace = ""
	resp.LocalDefaultAddressSpace = ""
	sendResponse(resp, w)
}

func ipamRequestPool(w http.ResponseWriter, r *http.Request) {
	resp := ipamapi.RequestPoolResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Error = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := ipamapi.RequestPoolRequest{}
	if err := json.Unmarshal(body, &req); err != nil {
		resp.Error = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	ipdkMutex.Lock()
	defer ipdkMutex.Unlock()
	_, ipamerr := ipdkIpam.NewPrefix(req.Pool)
	if ipamerr != nil {
		resp.Error = "Error: " + ipamerr.Error()
		sendResponse(resp, w)
		return
	}

	resp.PoolID = uuid.Generate().String()
	resp.Pool = req.Pool

	ipamMap.Lock()
	defer ipamMap.Unlock()
	ipamMap.count = ipamMap.count + 1
	ipamMap.m[resp.PoolID] = &ipamVal{
		subnet:  req.Pool,
	}

	sendResponse(resp, w)

	glog.Infof("INFO: Saved poolID [%s] with subnet [%s]", resp.PoolID, req.Pool)
}

func ipamReleasePool(w http.ResponseWriter, r *http.Request) {
	resp := ipamapi.ReleasePoolResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Error = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := ipamapi.ReleasePoolRequest{}
	if err := json.Unmarshal(body, &req); err != nil {
		resp.Error = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	ipamMap.Lock()
	defer ipamMap.Unlock()

	ipm := ipamMap.m[req.PoolID]
	ipamSubnet := ipm.subnet
	ipamMap.count = ipamMap.count - 1

	ipdkMutex.Lock()
	defer ipdkMutex.Unlock()

	delete(ipamMap.m, req.PoolID)

	_, ipamerr := ipdkIpam.DeletePrefix(ipamSubnet)
	if ipamerr != nil {
		resp.Error = "Error: " + ipamerr.Error()
		sendResponse(resp, w)
		return
	}

	sendResponse(resp, w)
}

func ipamRequestAddress(w http.ResponseWriter, r *http.Request) {
	resp := ipamapi.RequestAddressResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Error = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := ipamapi.RequestAddressRequest{}
	if err := json.Unmarshal(body, &req); err != nil {
		resp.Error = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	ipamMap.Lock()
	defer ipamMap.Unlock()
	ipm := ipamMap.m[req.PoolID]
	ipamSubnet := ipm.subnet

	if val, ok := req.Options["RequestAddressType"]; ok {
		if val == "com.docker.network.gateway" {
			glog.Info("INFO: Saving gateway address [%s]", req.Address)
			ipm.gateway = req.Address
		}
	}

	glog.Info("INFO: Found subnet [%s] for ID [%s]", ipamSubnet, req.PoolID)

	ipdkMutex.Lock()
	defer ipdkMutex.Unlock()

	//TODO: Should come from the subnet mask for the subnet
	if req.Address != "" {
		ip, ipamerr := ipdkIpam.AcquireSpecificIP(ipamSubnet, req.Address)
		if ipamerr != nil {
			glog.Error("ERROR: Specific IP %s not found in CIDR %s", req.Address, ipamSubnet)
			resp.Error = "Error: " + ipamerr.Error()
			sendResponse(resp, w)
			return
		}

		resp.Address = ip.IP.String() + "/24"
		glog.Info("INFO: Selected IP %v %v", ip.IP.String, resp.Address)
	} else {
		ip, ipamerr := ipdkIpam.AcquireIP(ipamSubnet)
		if ipamerr != nil {
			glog.Error("ERROR: Unable to acquire IP from subnet %s", ipamSubnet)
			resp.Error = "Error: " + ipamerr.Error()
			sendResponse(resp, w)
			return
		}

		resp.Address = ip.IP.String() + "/24"
		glog.Info("INFO: Selected IP %v %v", ip.IP.String, resp.Address)
	}
	sendResponse(resp, w)
}

func ipamReleaseAddress(w http.ResponseWriter, r *http.Request) {
	resp := ipamapi.ReleaseAddressResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Error = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := ipamapi.ReleaseAddressRequest{}
	if err := json.Unmarshal(body, &req); err != nil {
		resp.Error = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	ipamMap.Lock()
	defer ipamMap.Unlock()
	ipm := ipamMap.m[req.PoolID]
	ipamSubnet := ipm.subnet

	ipdkMutex.Lock()
	defer ipdkMutex.Unlock()
	ipamerr := ipdkIpam.ReleaseIPFromPrefix(ipamSubnet, req.Address)
	if ipamerr != nil {
		resp.Error = "Error: " + ipamerr.Error()
		sendResponse(resp, w)
		return
	}

	sendResponse(resp, w)
}

func dbTableInit(tables []string) (err error) {

	glog.Infof("dbInit Tables := %v", tables)
	for i, v := range tables {
		glog.Infof("table[%v] := %v, %v", i, v, []byte(v))
	}

	err = db.Update(func(tx *bolt.Tx) error {
		for _, table := range tables {
			_, err := tx.CreateBucketIfNotExists([]byte(table))
			if err != nil {
				return fmt.Errorf("Bucket creation error: %v %v", table, err)
			}
		}
		return nil
	})

	if err != nil {
		glog.Errorf("Table creation error %v", err)
	}

	return err
}

func dbAdd(table string, key string, value interface{}) (err error) {

	err = db.Update(func(tx *bolt.Tx) error {
		var v bytes.Buffer

		if err := gob.NewEncoder(&v).Encode(value); err != nil {
			glog.Errorf("Encode Error: %v %v", err, value)
			return err
		}

		bucket := tx.Bucket([]byte(table))
		if bucket == nil {
			return fmt.Errorf("Bucket %v not found", table)
		}

		err = bucket.Put([]byte(key), v.Bytes())
		if err != nil {
			return fmt.Errorf("Key Store error: %v %v %v %v", table, key, value, err)
		}
		return nil
	})

	return err
}

func dbDelete(table string, key string) (err error) {

	err = db.Update(func(tx *bolt.Tx) error {

		bucket := tx.Bucket([]byte(table))
		if bucket == nil {
			return fmt.Errorf("Bucket %v not found", table)
		}

		err = bucket.Delete([]byte(key))
		if err != nil {
			return fmt.Errorf("Key Delete error: %v %v ", key, err)
		}
		return nil
	})

	return err
}

func dbGet(table string, key string) (value interface{}, err error) {

	err = db.View(func(tx *bolt.Tx) error {

		bucket := tx.Bucket([]byte(table))
		if bucket == nil {
			return fmt.Errorf("Bucket %v not found", table)
		}

		val := bucket.Get([]byte(key))
		if val == nil {
			return nil
		}

		v := bytes.NewReader(val)
		if err := gob.NewDecoder(v).Decode(value); err != nil {
			glog.Errorf("Decode Error: %v %v %v", table, key, err)
			return err
		}

		return nil
	})

	return value, err
}

func initDb() error {

	options := bolt.Options{
		Timeout: 3 * time.Second,
	}

	var err error
	db, err = bolt.Open(dbFile, 0644, &options)
	if err != nil {
		return fmt.Errorf("dbInit failed %v", err)
	}

	tables := []string{"global", "nwMap", "epMap", "brMap"}
	if err := dbTableInit(tables); err != nil {
		return fmt.Errorf("dbInit failed %v", err)
	}

	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("nwMap"))

		err := b.ForEach(func(k, v []byte) error {
			vr := bytes.NewReader(v)
			nVal := &nwVal{}
			if err := gob.NewDecoder(vr).Decode(nVal); err != nil {
				return fmt.Errorf("Decode Error: %v %v %v", string(k), string(v), err)
			}
			nwMap.m[string(k)] = nVal
			glog.Infof("nwMap key=%v, value=%v\n", string(k), nVal)
			return nil
		})
		return err
	})

	if err != nil {
		return err
	}

	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("epMap"))

		err := b.ForEach(func(k, v []byte) error {
			vr := bytes.NewReader(v)
			eVal := &epVal{}
			if err := gob.NewDecoder(vr).Decode(eVal); err != nil {
				return fmt.Errorf("Decode Error: %v %v %v", string(k), string(v), err)
			}
			epMap.m[string(k)] = eVal
			glog.Infof("epMap key=%v, value=%v\n", string(k), eVal)
			return nil
		})
		return err
	})

	if err != nil {
		return err
	}

	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("brMap"))

		err := b.ForEach(func(k, v []byte) error {
			vr := bytes.NewReader(v)
			brVal := 0
			if err := gob.NewDecoder(vr).Decode(&brVal); err != nil {
				return fmt.Errorf("Decode Error: %v %v %v", string(k), string(v), err)
			}
			brMap.m[string(k)] = brVal
			glog.Infof("brMap key=%v, value=%v\n", string(k), brVal)
			return nil
		})
		return err
	})

	return err
}

func main() {
	var err error

	hostPorts = flag.Bool("hostports", false, "Enable veth ports on host for IPDK networks")

	flag.Parse()

	godotenv.Load("~/.ipdk/ipdk.env")

	// Check for namespace
	if nsID, err = netns.GetFromName(switchNS); err != nil {
		glog.Fatalf("Cannot find %s namespace, exiting [%v]", switchNS, err)
	}

	switchLoDev := &netlink.Device{}
	switchLoDev.LinkAttrs.Name = "lo"
	if err = netlink.LinkSetUp(switchLoDev); err != nil {
		glog.Fatalf("error setting loopback device up [%v]", err)
	}

	if err := initDb(); err != nil {
		glog.Fatalf("db init failed, quitting [%v]", err)
	}
	defer func() {
		err := db.Close()
		glog.Errorf("unable to close database [%v]", err)
	}()

	// create a ipamer with in memory storage
	// .FIXME: We're using memory backed storage, should probably use something on disk
	// More details here: https://github.com/metal-stack/go-ipam
	ipdkIpam = goipam.New()

	r := mux.NewRouter()
	r.HandleFunc("/Plugin.Activate", handlerPluginActivate)
	r.HandleFunc("/NetworkDriver.GetCapabilities", handlerGetCapabilities)
	r.HandleFunc("/NetworkDriver.CreateNetwork", handlerCreateNetwork)
	r.HandleFunc("/NetworkDriver.DeleteNetwork", handlerDeleteNetwork)
	r.HandleFunc("/NetworkDriver.CreateEndpoint", handlerCreateEndpoint)
	r.HandleFunc("/NetworkDriver.DeleteEndpoint", handlerDeleteEndpoint)
	r.HandleFunc("/NetworkDriver.EndpointOperInfo", handlerEndpointOperInfof)
	r.HandleFunc("/NetworkDriver.Join", handlerJoin)
	r.HandleFunc("/NetworkDriver.Leave", handlerLeave)
	r.HandleFunc("/NetworkDriver.DiscoverNew", handlerDiscoverNew)
	r.HandleFunc("/NetworkDriver.DiscoverDelete", handlerDiscoverDelete)
	r.HandleFunc("/NetworkDriver.ProgramExternalConnectivity", handlerExternalConnectivity)
	r.HandleFunc("/NetworkDriver.RevokeExternalConnectivity", handlerRevokeExternalConnectivity)

	r.HandleFunc("/IpamDriver.GetCapabilities", ipamGetCapabilities)
	r.HandleFunc("/IpamDriver.GetDefaultAddressSpaces", ipamGetDefaultAddressSpaces)
	r.HandleFunc("/IpamDriver.RequestPool", ipamRequestPool)
	r.HandleFunc("/IpamDriver.ReleasePool", ipamReleasePool)
	r.HandleFunc("/IpamDriver.RequestAddress", ipamRequestAddress)
	r.HandleFunc("/IpamDriver.ReleaseAddress", ipamReleaseAddress)

	r.HandleFunc("/", handler)
	err = http.ListenAndServe("127.0.0.1:9075", r)
	if err != nil {
		glog.Errorf("docker plugin http server failed, [%v]", err)
	}
}
