// Copyright 2012-2020 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// This set of end-to-end integration tests execute gosnmp against a real
// SNMP MIB-2 host. Potential test systems could include a router, NAS box, printer,
// or a linux box running snmpd, snmpsimd.py, etc.
//
// Ensure "gosnmp-test-host" is defined in your hosts file, and points to your
// generic test system.

// +build all end2end

package gosnmp

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func setupConnection(t *testing.T) {
	envTarget := os.Getenv("GOSNMP_TARGET")
	envPort := os.Getenv("GOSNMP_PORT")

	envTarget = "demo.snmplabs.com"
	envPort = "161"

	if len(envTarget) <= 0 {
		t.Skip("environment variable not set: GOSNMP_TARGET")
	}
	Default.Target = envTarget

	if len(envPort) <= 0 {
		t.Skip("environment variable not set: GOSNMP_PORT")
	}
	port, _ := strconv.ParseUint(envPort, 10, 16)
	Default.Port = uint16(port)

	err := Default.Connect()
	if err != nil {
		if len(envTarget) > 0 {
			t.Fatalf("Connection failed. Is snmpd reachable on %s:%s?\n(err: %v)",
				envTarget, envPort, err)
		}
	}
}

func setupConnectionIPv4(t *testing.T) {
	envTarget := os.Getenv("GOSNMP_TARGET_IPV4")
	envPort := os.Getenv("GOSNMP_PORT_IPV4")

	envTarget = "demo.snmplabs.com"
	envPort = "161"

	if len(envTarget) <= 0 {
		t.Skip("environment variable not set: GOSNMP_TARGET_IPV4")
	}
	Default.Target = envTarget

	if len(envPort) <= 0 {
		t.Skip("environment variable not set: GOSNMP_PORT_IPV4")
	}
	port, _ := strconv.ParseUint(envPort, 10, 16)
	Default.Port = uint16(port)

	err := Default.ConnectIPv4()
	if err != nil {
		if len(envTarget) > 0 {
			t.Fatalf("Connection failed. Is snmpd reachable on %s:%s?\n(err: %v)",
				envTarget, envPort, err)
		}
	}
}

/*
TODO work out ipv6 networking, etc

func setupConnectionIPv6(t *testing.T) {
	envTarget := os.Getenv("GOSNMP_TARGET_IPV6")
	envPort := os.Getenv("GOSNMP_PORT_IPV6")

	if len(envTarget) <= 0 {
		t.Error("environment variable not set: GOSNMP_TARGET_IPV6")
	}
	Default.Target = envTarget

	if len(envPort) <= 0 {
		t.Error("environment variable not set: GOSNMP_PORT_IPV6")
	}
	port, _ := strconv.ParseUint(envPort, 10, 16)
	Default.Port = uint16(port)

	err := Default.ConnectIPv6()
	if err != nil {
		if len(envTarget) > 0 {
			t.Fatalf("Connection failed. Is snmpd reachable on %s:%s?\n(err: %v)",
				envTarget, envPort, err)
		}
	}
}
*/

func TestGenericBasicGet(t *testing.T) {
	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestGenericBasicGetIPv4Only(t *testing.T) {
	setupConnectionIPv4(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

/*
func TestGenericBasicGetIPv6Only(t *testing.T) {
	setupConnectionIPv6(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}
*/

func TestGenericMultiGet(t *testing.T) {
	setupConnection(t)
	defer Default.Conn.Close()

	oids := []string{
		".1.3.6.1.2.1.1.1.0", // SNMP MIB-2 sysDescr
		".1.3.6.1.2.1.1.5.0", // SNMP MIB-2 sysName
	}
	result, err := Default.Get(oids)
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 2 {
		t.Fatalf("Expected result of size 2")
	}
	for _, v := range result.Variables {
		if v.Type != OctetString {
			t.Fatalf("Expected OctetString")
		}
	}
}

func TestGenericGetNext(t *testing.T) {
	setupConnection(t)
	defer Default.Conn.Close()

	sysDescrOid := ".1.3.6.1.2.1.1.1.0" // SNMP MIB-2 sysDescr
	result, err := Default.GetNext([]string{sysDescrOid})
	if err != nil {
		t.Fatalf("GetNext() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Name == sysDescrOid {
		t.Fatalf("Expected next OID")
	}
}

func TestGenericWalk(t *testing.T) {
	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.WalkAll("")
	if err != nil {
		t.Fatalf("WalkAll() Failed with error => %v", err)
	}
	if len(result) <= 1 {
		t.Fatalf("Expected multiple values, got %d", len(result))
	}
}

func TestGenericBulkWalk(t *testing.T) {
	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.BulkWalkAll("")
	if err != nil {
		t.Fatalf("BulkWalkAll() Failed with error => %v", err)
	}
	if len(result) <= 1 {
		t.Fatalf("Expected multiple values, got %d", len(result))
	}
}

// Standard exception/error tests

func TestMaxOids(t *testing.T) {
	setupConnection(t)
	defer Default.Conn.Close()

	Default.MaxOids = 1

	var err error
	oids := []string{".1.3.6.1.2.1.1.7.0",
		".1.3.6.1.2.1.2.2.1.10.1"} // 2 arbitrary Oids
	errString := "oid count (2) is greater than MaxOids (1)"

	_, err = Default.Get(oids)
	if err == nil {
		t.Fatalf("Expected too many oids failure. Got nil")
	} else if err.Error() != errString {
		t.Fatalf("Expected too many oids failure. Got => %v", err)
	}

	_, err = Default.GetNext(oids)
	if err == nil {
		t.Fatalf("Expected too many oids failure. Got nil")
	} else if err.Error() != errString {
		t.Fatalf("Expected too many oids failure. Got => %v", err)
	}

	_, err = Default.GetBulk(oids, 0, 0)
	if err == nil {
		t.Fatalf("Expected too many oids failure. Got nil")
	} else if err.Error() != errString {
		t.Fatalf("Expected too many oids failure. Got => %v", err)
	}
}

func TestGenericFailureUnknownHost(t *testing.T) {
	unknownHost := fmt.Sprintf("gosnmp-test-unknown-host-%d", time.Now().UTC().UnixNano())
	Default.Target = unknownHost
	err := Default.Connect()
	if err == nil {
		t.Fatalf("Expected connection failure due to unknown host")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "no such host") {
		t.Fatalf("Expected connection error of type 'no such host'! Got => %v", err)
	}
	_, err = Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err == nil {
		t.Fatalf("Expected get to fail due to missing connection")
	}
}

func TestGenericFailureConnectionTimeout(t *testing.T) {
	envTarget := os.Getenv("GOSNMP_TARGET")
	if len(envTarget) <= 0 {
		t.Skip("local testing - skipping this slow one") // TODO test tag, or something
	}

	Default.Target = "198.51.100.1" // Black hole
	err := Default.Connect()
	if err != nil {
		t.Fatalf("Did not expect connection error with IP address")
	}
	_, err = Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err == nil {
		t.Fatalf("Expected Get() to fail due to invalid IP")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("Expected timeout error. Got => %v", err)
	}
}

func TestGenericFailureConnectionRefused(t *testing.T) {
	Default.Target = "127.0.0.1"
	Default.Port = 1 // Don't expect SNMP to be running here!
	err := Default.Connect()
	if err != nil {
		t.Fatalf("Did not expect connection error with IP address")
	}
	_, err = Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err == nil {
		t.Fatalf("Expected Get() to fail due to invalid port")
	}
	if !(strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "forcibly closed")) {
		t.Fatalf("Expected connection refused error. Got => %v", err)
	}
}


// GO SNMP credentials table
var _ = map[string][]string {
	NoAuth.String() + NoPriv.String():	{ "noAuthNoPrivUser", "", "" },

	MD5.String() + NoPriv.String(): 	{ "authMD5OnlyUser", "authkey1", "" },
	MD5.String() + DES.String(): 		{ "authMD5PrivDESUser", "authkey1", "privkey1" },
	MD5.String() + AES.String(): 		{ "authMD5PrivAESUser", "authkey1", "privkey1" },
	MD5.String() + AES192.String():		{ "authMD5PrivAES192BlmtUser", "authkey1", "privkey1" },
	MD5.String() + AES192C.String():	{ "authMD5PrivAES192User", "authkey1", "privkey1" },
	MD5.String() + AES256.String():		{ "authMD5PrivAES256BlmtUser", "authkey1", "privkey1" },
	MD5.String() + AES256C.String():	{ "authMD5PrivAES256User", "authkey1", "privkey1" },

	SHA.String() + NoPriv.String(): 	{ "authSHAOnlyUser", "authkey1", "" },
	SHA.String() + DES.String(): 		{ "authSHAPrivDESUser", "authkey1", "privkey1" },
	SHA.String() + AES.String(): 		{ "authSHAPrivAESUser", "authkey1", "privkey1" },
	SHA.String() + AES192.String():		{ "authSHAPrivAES192BlmtUser", "authkey1", "privkey1" },
	SHA.String() + AES192C.String():	{ "authSHAPrivAES192User", "authkey1", "privkey1" },
	SHA.String() + AES256.String():		{ "authSHAPrivAES256BlmtUser", "authkey1", "privkey1" },
	SHA.String() + AES256C.String():	{ "authSHAPrivAES256User", "authkey1", "privkey1" },

	SHA224.String() + NoPriv.String(): 	{ "authSHA224OnlyUser", "authkey1", "" },
	SHA224.String() + DES.String(): 	{ "authSHA224PrivDESUser", "authkey1", "privkey1" },
	SHA224.String() + AES.String(): 	{ "authSHA224PrivAESUser", "authkey1", "privkey1" },
	SHA224.String() + AES192.String():	{ "authSHA224PrivAES192BlmtUser", "authkey1", "privkey1" },
	SHA224.String() + AES192C.String():	{ "authSHA224PrivAES192User", "authkey1", "privkey1" },
	SHA224.String() + AES256.String():	{ "authSHA224PrivAES256BlmtUser", "authkey1", "privkey1" },
	SHA224.String() + AES256C.String():	{ "authSHA224PrivAES256User", "authkey1", "privkey1" },

	SHA256.String() + NoPriv.String(): 	{ "authSHA256OnlyUser", "authkey1", "" },
	SHA256.String() + DES.String(): 	{ "authSHA256PrivDESUser", "authkey1", "privkey1" },
	SHA256.String() + AES.String(): 	{ "authSHA256PrivAESUser", "authkey1", "privkey1" },
	SHA256.String() + AES192.String():	{ "authSHA256PrivAES192BlmtUser", "authkey1", "privkey1" },
	SHA256.String() + AES192C.String():	{ "authSHA256PrivAES192User", "authkey1", "privkey1" },
	SHA256.String() + AES256.String():	{ "authSHA256PrivAES256BlmtUser", "authkey1", "privkey1" },
	SHA256.String() + AES256C.String():	{ "authSHA256PrivAES256User", "authkey1", "privkey1" },

	SHA384.String() + NoPriv.String(): 	{ "authSHA384OnlyUser", "authkey1", "" },
	SHA384.String() + DES.String(): 	{ "authSHA384PrivDESUser", "authkey1", "privkey1" },
	SHA384.String() + AES.String(): 	{ "authSHA384PrivAESUser", "authkey1", "privkey1" },
	SHA384.String() + AES192.String():	{ "authSHA384PrivAES192BlmtUser", "authkey1", "privkey1" },
	SHA384.String() + AES192C.String():	{ "authSHA384PrivAES192User", "authkey1", "privkey1" },
	SHA384.String() + AES256.String():	{ "authSHA384PrivAES256BlmtUser", "authkey1", "privkey1" },
	SHA384.String() + AES256C.String():	{ "authSHA384PrivAES256User", "authkey1", "privkey1" },

	SHA512.String() + NoPriv.String(): 	{ "authSHA512OnlyUser", "authkey1", "" },
	SHA512.String() + DES.String(): 	{ "authSHA512PrivDESUser", "authkey1", "privkey1" },
	SHA512.String() + AES.String(): 	{ "authSHA512PrivAESUser", "authkey1", "privkey1" },
	SHA512.String() + AES192.String():	{ "authSHA512PrivAES192BlmtUser", "authkey1", "privkey1" },
	SHA512.String() + AES192C.String():	{ "authSHA512PrivAES192User", "authkey1", "privkey1" },
	SHA512.String() + AES256.String():	{ "authSHA512PrivAES256BlmtUser", "authkey1", "privkey1" },
	SHA512.String() + AES256C.String():	{ "authSHA512PrivAES256User", "authkey1", "privkey1" },
}

// Credentials table for public demo.snmplabs.org
var authenticationCredentials = map[string][]string {
	NoAuth.String() + NoPriv.String():	{ "usr-none-none", "", "" },

	MD5.String() + NoPriv.String(): 	{ "usr-md5-none", "authkey1", "" },
	MD5.String() + DES.String(): 		{ "usr-md5-des", "authkey1", "privkey1" },
	MD5.String() + AES.String(): 		{ "usr-md5-aes", "authkey1", "privkey1" },
	MD5.String() + AES192.String():		{ "usr-md5-aes192-blmt", "authkey1", "privkey1" },
	MD5.String() + AES192C.String():	{ "usr-md5-aes192", "authkey1", "privkey1" },
	MD5.String() + AES256.String():		{ "usr-md5-aes256-blmt", "authkey1", "privkey1" },
	MD5.String() + AES256C.String():	{ "usr-md5-aes256", "authkey1", "privkey1" },

	SHA.String() + NoPriv.String(): 	{ "usr-sha-none", "authkey1", "" },
	SHA.String() + DES.String(): 		{ "usr-sha-des", "authkey1", "privkey1" },
	SHA.String() + AES.String(): 		{ "usr-sha-aes", "authkey1", "privkey1" },
	SHA.String() + AES192.String():		{ "usr-sha-aes192-blmt", "authkey1", "privkey1" },
	SHA.String() + AES192C.String():	{ "usr-sha-aes192", "authkey1", "privkey1" },
	SHA.String() + AES256.String():		{ "usr-sha-aes256-blmt", "authkey1", "privkey1" },
	SHA.String() + AES256C.String():	{ "usr-sha-aes256", "authkey1", "privkey1" },

	SHA224.String() + NoPriv.String(): 	{ "usr-sha224-none", "authkey1", "" },
	SHA224.String() + DES.String(): 	{ "usr-sha224-des", "authkey1", "privkey1" },
	SHA224.String() + AES.String(): 	{ "usr-sha224-aes", "authkey1", "privkey1" },
	SHA224.String() + AES192.String():	{ "usr-sha224-aes192-blmt", "authkey1", "privkey1" },
	SHA224.String() + AES192C.String():	{ "usr-sha224-aes192", "authkey1", "privkey1" },
	SHA224.String() + AES256.String():	{ "usr-sha224-aes256-blmt", "authkey1", "privkey1" },
	SHA224.String() + AES256C.String():	{ "usr-sha224-aes256", "authkey1", "privkey1" },

	SHA256.String() + NoPriv.String(): 	{ "usr-sha256-none", "authkey1", "" },
	SHA256.String() + DES.String(): 	{ "usr-sha256-des", "authkey1", "privkey1" },
	SHA256.String() + AES.String(): 	{ "usr-sha256-aes", "authkey1", "privkey1" },
	SHA256.String() + AES192.String():	{ "usr-sha256-aes192-blmt", "authkey1", "privkey1" },
	SHA256.String() + AES192C.String():	{ "usr-sha256-aes192", "authkey1", "privkey1" },
	SHA256.String() + AES256.String():	{ "usr-sha256-aes256-blmt", "authkey1", "privkey1" },
	SHA256.String() + AES256C.String():	{ "usr-sha256-aes256", "authkey1", "privkey1" },

	SHA384.String() + NoPriv.String(): 	{ "usr-sha384-none", "authkey1", "" },
	SHA384.String() + DES.String(): 	{ "usr-sha384-des", "authkey1", "privkey1" },
	SHA384.String() + AES.String(): 	{ "usr-sha384-aes", "authkey1", "privkey1" },
	SHA384.String() + AES192.String():	{ "usr-sha384-aes192-blmt", "authkey1", "privkey1" },
	SHA384.String() + AES192C.String():	{ "usr-sha384-aes192", "authkey1", "privkey1" },
	SHA384.String() + AES256.String():	{ "usr-sha384-aes256-blmt", "authkey1", "privkey1" },
	SHA384.String() + AES256C.String():	{ "usr-sha384-aes256", "authkey1", "privkey1" },

	SHA512.String() + NoPriv.String(): 	{ "usr-sha512-none", "authkey1", "" },
	SHA512.String() + DES.String(): 	{ "usr-sha512-des", "authkey1", "privkey1" },
	SHA512.String() + AES.String(): 	{ "usr-sha512-aes", "authkey1", "privkey1" },
	SHA512.String() + AES192.String():	{ "usr-sha512-aes192-blmt", "authkey1", "privkey1" },
	SHA512.String() + AES192C.String():	{ "usr-sha512-aes192", "authkey1", "privkey1" },
	SHA512.String() + AES256.String():	{ "usr-sha512-aes256-blmt", "authkey1", "privkey1" },
	SHA512.String() + AES256C.String():	{ "usr-sha512-aes256", "authkey1", "privkey1" },
}

func getUserName(authProtocol SnmpV3AuthProtocol, privProtocol SnmpV3PrivProtocol) string {
	return authenticationCredentials[authProtocol.String() + privProtocol.String()][0]
}

func getAuthKey(authProtocol SnmpV3AuthProtocol, privProtocol SnmpV3PrivProtocol) string {
	return authenticationCredentials[authProtocol.String() + privProtocol.String()][1]
}

func getPrivKey(authProtocol SnmpV3AuthProtocol, privProtocol SnmpV3PrivProtocol) string {
	return authenticationCredentials[authProtocol.String() + privProtocol.String()][2]
}

func TestSnmpV3NoAuthNoPrivBasicGet(t *testing.T) {
	Default.Version = Version3
	Default.MsgFlags = NoAuthNoPriv
	Default.SecurityModel = UserSecurityModel
//	Default.SecurityParameters = &UsmSecurityParameters{UserName: "noAuthNoPrivUser"}
	Default.SecurityParameters = &UsmSecurityParameters{ UserName: getUserName(NoAuth, NoPriv)}
	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestSnmpV3AuthMD5NoPrivGet(t *testing.T) {
	Default.Version = Version3
	Default.MsgFlags = AuthNoPriv
	Default.SecurityModel = UserSecurityModel
//	Default.SecurityParameters = &UsmSecurityParameters{UserName: "authMD5OnlyUser", AuthenticationProtocol: MD5, AuthenticationPassphrase: "testingpass0123456789"}
	Default.SecurityParameters = &UsmSecurityParameters{UserName: getUserName(MD5, NoPriv), AuthenticationProtocol: MD5, AuthenticationPassphrase: getAuthKey(MD5, NoPriv)}
	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestSnmpV3AuthSHANoPrivGet(t *testing.T) {
	Default.Version = Version3
	Default.MsgFlags = AuthNoPriv
	Default.SecurityModel = UserSecurityModel
//	Default.SecurityParameters = &UsmSecurityParameters{UserName: "authSHAOnlyUser", AuthenticationProtocol: SHA, AuthenticationPassphrase: "testingpass9876543210"}
	Default.SecurityParameters = &UsmSecurityParameters{UserName: getUserName(SHA, NoPriv), AuthenticationProtocol: SHA, AuthenticationPassphrase: getAuthKey(SHA, NoPriv)}
	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestSnmpV3AuthSHAPrivAESGet(t *testing.T) {
	Default.Version = Version3
	Default.MsgFlags = AuthPriv
	Default.SecurityModel = UserSecurityModel
	//	Default.SecurityParameters = &UsmSecurityParameters{UserName: "authSHAOnlyUser", AuthenticationProtocol: SHA, AuthenticationPassphrase: "testingpass9876543210"}
	Default.SecurityParameters = &UsmSecurityParameters{
		UserName: getUserName(SHA, AES),
		AuthenticationProtocol: SHA, AuthenticationPassphrase: getAuthKey(SHA, AES),
		PrivacyProtocol: AES, PrivacyPassphrase: getPrivKey(SHA, AES),
	}
	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestSnmpV3AuthSHAPrivAES256CGet(t *testing.T) {
	Default.Version = Version3
	Default.MsgFlags = AuthPriv
	Default.SecurityModel = UserSecurityModel
	//	Default.SecurityParameters = &UsmSecurityParameters{UserName: "authSHAOnlyUser", AuthenticationProtocol: SHA, AuthenticationPassphrase: "testingpass9876543210"}
	Default.SecurityParameters = &UsmSecurityParameters{
		UserName: getUserName(SHA, AES256C),
		AuthenticationProtocol: SHA, AuthenticationPassphrase: getAuthKey(SHA, AES256C),
		PrivacyProtocol: AES256C, PrivacyPassphrase: getPrivKey(SHA, AES256C),
	}
	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestSnmpV3AuthSHA224NoPrivGet(t *testing.T) {
	Default.Version = Version3
	Default.MsgFlags = AuthNoPriv
	Default.SecurityModel = UserSecurityModel
//	Default.SecurityParameters = &UsmSecurityParameters{UserName: "authSHA224OnlyUser", AuthenticationProtocol: SHA224, AuthenticationPassphrase: "testingpass5123456"}
	Default.SecurityParameters = &UsmSecurityParameters{UserName: getUserName(SHA224, NoPriv), AuthenticationProtocol: SHA224, AuthenticationPassphrase: getAuthKey(SHA224, NoPriv)}
	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestSnmpV3AuthSHA256NoPrivGet(t *testing.T) {
	Default.Version = Version3
	Default.MsgFlags = AuthNoPriv
	Default.SecurityModel = UserSecurityModel
//	Default.SecurityParameters = &UsmSecurityParameters{UserName: "authSHA256OnlyUser", AuthenticationProtocol: SHA256, AuthenticationPassphrase: "testingpass5223456"}
	Default.SecurityParameters = &UsmSecurityParameters{UserName: getUserName(SHA256, NoPriv), AuthenticationProtocol: SHA256, AuthenticationPassphrase: getAuthKey(SHA256, NoPriv)}
	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestSnmpV3AuthSHA384NoPrivGet(t *testing.T) {
	Default.Version = Version3
	Default.MsgFlags = AuthNoPriv
	Default.SecurityModel = UserSecurityModel
//	Default.SecurityParameters = &UsmSecurityParameters{UserName: "authSHA384OnlyUser", AuthenticationProtocol: SHA384, AuthenticationPassphrase: "testingpass5323456"}
	Default.SecurityParameters = &UsmSecurityParameters{UserName: getUserName(SHA384, NoPriv), AuthenticationProtocol: SHA384, AuthenticationPassphrase: getAuthKey(SHA384, NoPriv)}
	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestSnmpV3AuthSHA512NoPrivGet(t *testing.T) {
	Default.Version = Version3
	Default.MsgFlags = AuthNoPriv
	Default.SecurityModel = UserSecurityModel
//	Default.SecurityParameters = &UsmSecurityParameters{UserName: "authSHA512OnlyUser", AuthenticationProtocol: SHA512, AuthenticationPassphrase: "testingpass5423456"}
	Default.SecurityParameters = &UsmSecurityParameters{UserName: getUserName(SHA512, NoPriv), AuthenticationProtocol: SHA512, AuthenticationPassphrase: getAuthKey(SHA512, NoPriv)}
	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestSnmpV3AuthSHA512PrivAES192Get(t *testing.T) {
	Default.Version = Version3
	Default.MsgFlags = AuthPriv
	Default.SecurityModel = UserSecurityModel
	//	Default.SecurityParameters = &UsmSecurityParameters{UserName: "authSHA512OnlyUser", AuthenticationProtocol: SHA512, AuthenticationPassphrase: "testingpass5423456"}
	Default.SecurityParameters = &UsmSecurityParameters{
		UserName: getUserName(SHA512, AES192),
		AuthenticationProtocol: SHA512, AuthenticationPassphrase: getAuthKey(SHA512, AES192),
		PrivacyProtocol: AES192, PrivacyPassphrase: getPrivKey(SHA512, AES192),
	}

	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestSnmpV3AuthSHA512PrivAES256CGet(t *testing.T) {
	Default.Version = Version3
	Default.MsgFlags = AuthPriv
	Default.SecurityModel = UserSecurityModel
	//	Default.SecurityParameters = &UsmSecurityParameters{UserName: "authSHAOnlyUser", AuthenticationProtocol: SHA, AuthenticationPassphrase: "testingpass9876543210"}
	Default.SecurityParameters = &UsmSecurityParameters{
		UserName: getUserName(SHA512, AES256C),
		AuthenticationProtocol: SHA512, AuthenticationPassphrase: getAuthKey(SHA512, AES256C),
		PrivacyProtocol: AES256C, PrivacyPassphrase: getPrivKey(SHA512, AES256C),
	}
	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestSnmpV3AuthMD5PrivDESGet(t *testing.T) {
	Default.Version = Version3
	Default.MsgFlags = AuthPriv
	Default.SecurityModel = UserSecurityModel
	//Default.SecurityParameters = &UsmSecurityParameters{UserName: "authMD5PrivDESUser",
	//	AuthenticationProtocol:   MD5,
	//	AuthenticationPassphrase: "testingpass9876543210",
	//	PrivacyProtocol:          DES,
	//	PrivacyPassphrase:        "testingpass9876543210"}

	Default.SecurityParameters = &UsmSecurityParameters{UserName: getUserName(MD5, DES),
		AuthenticationProtocol:   MD5,
		AuthenticationPassphrase: getAuthKey(MD5, DES),
		PrivacyProtocol:          DES,
		PrivacyPassphrase:        getPrivKey(MD5, DES)}

	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestSnmpV3AuthSHAPrivDESGet(t *testing.T) {
	Default.Version = Version3
	Default.MsgFlags = AuthPriv
	Default.SecurityModel = UserSecurityModel
	//Default.SecurityParameters = &UsmSecurityParameters{UserName: "authSHAPrivDESUser",
	//	AuthenticationProtocol:   SHA,
	//	AuthenticationPassphrase: "testingpassabc6543210",
	//	PrivacyProtocol:          DES,
	//	PrivacyPassphrase:        "testingpassabc6543210"}
	Default.SecurityParameters = &UsmSecurityParameters{UserName: getUserName(SHA, DES),
		AuthenticationProtocol:   SHA,
		AuthenticationPassphrase: getAuthKey(SHA, DES),
		PrivacyProtocol:          DES,
		PrivacyPassphrase:        getPrivKey(SHA, DES)}

	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestSnmpV3AuthMD5PrivAESGet(t *testing.T) {
	Default.Version = Version3
	Default.MsgFlags = AuthPriv
	Default.SecurityModel = UserSecurityModel
	//Default.SecurityParameters = &UsmSecurityParameters{UserName: "authMD5PrivAESUser",
	//	AuthenticationProtocol:   MD5,
	//	AuthenticationPassphrase: "AEStestingpass9876543210",
	//	PrivacyProtocol:          AES,
	//	PrivacyPassphrase:        "AEStestingpass9876543210"}

	Default.SecurityParameters = &UsmSecurityParameters{UserName: getUserName(MD5, AES),
		AuthenticationProtocol:   MD5,
		AuthenticationPassphrase: getAuthKey(MD5, AES),
		PrivacyProtocol:          AES,
		PrivacyPassphrase:        getPrivKey(MD5, AES)}

	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestSnmpV3PrivEmptyPrivatePassword(t *testing.T) {
	Default.Version = Version3
	Default.MsgFlags = AuthPriv
	Default.SecurityModel = UserSecurityModel
	//Default.SecurityParameters = &UsmSecurityParameters{UserName: "authSHAPrivAESUser",
	//	AuthenticationProtocol:   SHA,
	//	AuthenticationPassphrase: "AEStestingpassabc6543210",
	//	PrivacyProtocol:          AES,
	//	PrivacyPassphrase:        ""}
	Default.SecurityParameters = &UsmSecurityParameters{UserName: getUserName(SHA, AES),
		AuthenticationProtocol:   SHA,
		AuthenticationPassphrase: getAuthKey(SHA, AES),
		PrivacyProtocol:          AES,
		PrivacyPassphrase:        ""}

	err := Default.Connect()
	if err == nil {
		t.Fatalf("Expected validation error for empty PrivacyPassphrase")
	}
}

func TestSnmpV3AuthNoPrivEmptyPrivatePassword(t *testing.T) {
	Default.Version = Version3
	Default.MsgFlags = AuthNoPriv
	Default.SecurityModel = UserSecurityModel
	//Default.SecurityParameters = &UsmSecurityParameters{UserName: "authSHAOnlyUser",
	//	AuthenticationProtocol:   SHA,
	//	AuthenticationPassphrase: "testingpass9876543210",
	//	PrivacyProtocol:          AES,
	//	PrivacyPassphrase:        ""}
	Default.SecurityParameters = &UsmSecurityParameters{UserName: getUserName(SHA, NoPriv),
		AuthenticationProtocol:   SHA,
		AuthenticationPassphrase: getAuthKey(SHA, NoPriv),
		PrivacyProtocol:          AES,
		PrivacyPassphrase:        getPrivKey(SHA, NoPriv)}

	err := Default.Connect()
	if err == nil {
		t.Fatalf("Expected validation error for empty PrivacyPassphrase")
	}

}
