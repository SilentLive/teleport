/*
Copyright 2018 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"fmt"

	"github.com/gravitational/teleport"
	"github.com/gravitational/trace"

	"github.com/sirupsen/logrus"
)

var log = logrus.WithFields(logrus.Fields{
	trace.Component: teleport.ComponentSOCKS,
})

const (
	socks4Version                 byte = 0x04
	socks5Version                 byte = 0x05
	socks5Reserved                byte = 0x00
	socks5AuthNotRequired         byte = 0x00
	socks5AuthNoAcceptableMethods byte = 0xFF
	socks5CommandConnect          byte = 0x01
	socks5AddressTypeIPv4         byte = 0x01
	socks5AddressTypeDomainName   byte = 0x03
	socks5AddressTypeIPv6         byte = 0x04
	socks5Succeeded               byte = 0x00
)

func SocksHandshake(client *NodeClient, incoming net.Conn) {
	//defer incoming.Close()
	//log.Debugf("nodeClient.dynamicProxyConnection(%v) started", incoming.RemoteAddr())

	version, err := readVersion()
	if err != nil {
		log.Errorf("Unable to read version: %v.", err)
		return
	}

}

func readVersion() (byte, error) {

	version := []byte{0}
	_, err := incoming.Read(version)
	if err != nil {
		log.Errorf("Failed to read first byte of %v", incoming)
		return
	}
	switch version[0] {
	case socks5Version:
		socks5ProxyConnection(client, incoming)
	case socks4Version:
		log.Errorf("SOCKS4 dynamic port forwarding is no yet supported (%v)", incoming)
	default:
		log.Errorf("Unknown dynamic port forwarding protocol requested by (%v)", incoming)
	}
}

func socks5ProxyAuthenticate(incoming net.Conn) error {
	nmethods, err := readByte(incoming)
	if err != nil {
		return err
	}

	chosenMethod := socks5AuthNoAcceptableMethods
	for i := byte(0); i < nmethods; i++ {
		method, err := readByte(incoming)
		if err != nil {
			return err
		}
		if method == socks5AuthNotRequired {
			chosenMethod = socks5AuthNotRequired
		}
	}

	_, err = incoming.Write([]byte{socks5Version, chosenMethod})
	if err != nil {
		return err
	}

	if chosenMethod == socks5AuthNoAcceptableMethods {
		return errors.New("Unable to find suitable authentication method")
	}

	return nil
}

func socks5ProxyConnectRequest(incoming net.Conn) (remoteAddr string, err error) {
	header := make([]byte, 4)
	_, err = io.ReadFull(incoming, header)
	if err != nil {
		return
	}
	if !bytes.Equal(header[0:3], []byte{socks5Version, socks5CommandConnect, socks5Reserved}) {
		err = errors.New("only connect command is supported for SOCKS5")
		return
	}

	var ip net.IP
	var remoteHost string
	switch header[3] {
	case socks5AddressTypeIPv4:
		ip = make([]byte, net.IPv4len)
	case socks5AddressTypeIPv6:
		ip = make([]byte, net.IPv6len)
	case socks5AddressTypeDomainName:
		var domainNameLen byte
		domainNameLen, err = readByte(incoming)
		if err != nil {
			return
		}
		remoteAddrBuf := make([]byte, domainNameLen)
		_, err = io.ReadFull(incoming, remoteAddrBuf)
		if err != nil {
			return
		}
		remoteHost = string(remoteAddrBuf)
	default:
		err = errors.New("Unsupported address type for SOCKS5 connect request")
		return
	}

	if ip != nil {
		// Still need to read the ip address
		_, err = io.ReadFull(incoming, ip)
		if err != nil {
			return
		}
		remoteHost = ip.String()
	}

	var remotePort uint16
	err = binary.Read(incoming, binary.BigEndian, &remotePort)
	if err != nil {
		return
	}

	// Send the same minimal response as openSSH does
	response := make([]byte, 4+net.IPv4len+2)
	copy(response, []byte{socks5Version, socks5Succeeded, socks5Reserved, socks5AddressTypeIPv4})
	_, err = incoming.Write(response)
	if err != nil {
		return
	}

	return net.JoinHostPort(remoteHost, strconv.Itoa(int(remotePort))), nil
}

func socks5ProxyConnection(client *NodeClient, incoming net.Conn) {
	err := socks5ProxyAuthenticate(incoming)
	if nil != err {
		log.Errorf("socks5ProxyConnection unable to authenticate (%v) [%v]", incoming, err)
		return
	}

	remoteAddr, err := socks5ProxyConnectRequest(incoming)
	if nil != err {
		log.Errorf("socks5ProxyConnection did not receive connect (%v) [%v]", incoming, err)
		return
	}

	proxyConnection(client, incoming, remoteAddr)
}

func readByte(reader io.Reader) (byte, error) {
	buf := []byte{0}
	_, err := io.ReadFull(reader, buf)
	return buf[0], err
}
