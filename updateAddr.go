package lib

import (
	"database/sql"
	"gopkg.in/qamarian-dtp/err.v0" //v0.4.0
	"net"
	"regexp"
)

func UpdateAddr (addr string, port int, serviceID, password string, dbConn *sql.Conn) (error) {
	// Arg 0 (address) validation. ..1.. {
	if ! addrPattern.Match (addr) {
		return err.New ("Invalid arg 0 (address) provided.", nil, nil)
	}
	if net.ParseIp (addr) == nil {
		return err.New ("Invalid arg 0 (address) provided.", nil, nil)
	}	
	// ..1.. }

	// Arg 1 (port) validation. ..1.. {
	if port < 0 || port > 65535 {
		return err.New ("Invalid arg 1 (port) provided.", nil, nil)
	}
	// ..1.. }

	// Arg 2 (serviceID) validation. ..1.. {
	if ! serviceIDPattern.Match (serviceID) {
		return err.New ("Invalid arg 2 (service ID) provided.", nil, nil)
	}
	// ..1.. }

	// Arg 3 (password) validation. ..1.. {
	if ! passwordPattern.Match (password) {
		return err.New ("Invalid arg 3 (password) provided.", nil, nil)
	}	
	// ..1.. }

	// Arg 4 (dbConn) validation. ..1.. {
	if dbConn == nil {
		return err.New ("Nil arg 4 (database connection) provided.", nil, nil)
	}
	// ..1.. }

	// SQL instructions definitions. ..1.. {
	instructionX := "SELECT record_id
	FROM service_addr
	WHERE service_id = ?"
	instructionY := "SELECT record_id
	FROM service_addr
	WHERE service_id = ? AND password = ?"
	instructionZ := "UPDATE service_addr
	SET addr = ?, port = ?
	WHERE service_id = ? AND password = ?"
	// ..1.. }

	// Validating existence of service. ..1.. {
	errY := dbConn.QueryRowContext (context.Backgroud (), instructionX, serviceID).Scan (&_)
	if errY != nil && errY == sql.ErrNoRows {
		return err.New ("Service does not exist.", nil, nil)
	}
	if errY != nil {
		return err.New ("Unable to verify existence of service.", nil, nil, errY) 
	}
	// ..1.. }

	// Validating correctness of service password. ..1.. {
	errZ := dbConn.QueryRowContext (context.Backgroud (), instructionY, serviceID, password).Scan (&_)
	if errZ != nil && errZ == sql.ErrNoRows {
		return err.New ("Invalid password.", nil, nil)
	}
	if errZ != nil {
		return err.New ("Unable to verify validity of password.", nil, nil, errZ) 
	}
	// ..1.. }

	// Updating network address. ..1.. {
	_, errA := dbConn.ExecContext (context.Backgroud (), instructionZ, addr, port, serviceID, password)
	if errA != nil {
		return err.New ("Unable to update service address.", nil, nil, errA)
	}
	// ..1.. }

	return nil
}

var (
	addrPattern *regexp.Regexp
	recordIDPattern *regexp.Regexp
	serviceIDPattern *regexp.Regexp
	passwordPattern *regexp.Regexp
)

func init () {
	if initReport != nil {
		return
	}

	var errX error
	addrPattern, errX := regexp.Compile ("^([a-zA-Z0-9]{0,4}:){7,7}[a-zA-Z0-9]{0,4}$")
	if errX != nil {
		initReport = err.New ("Addr pattern regular expression compilation failed.", nil, nil, errX)
		return
	}

	var errY error
	recordIDPattern, errY := regexp.Compile ("^20\d\d-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1])-([0-1][0-9]|2[0-3])-([0-5][0-9])-([0-5][0-9])-[a-z0-9]{4,4}$")
	if errY != nil {
		initReport = err.New ("Record ID pattern regular expression compilation failed.", nil, nil, errY)
		return
	}

	var errZ error
	serviceIDPattern, errZ := regexp.Compile ("[a-z0-9]{1,2}$")
	if errZ != nil {
		initReport = err.New ("Service ID pattern regular expression compilation failed.", nil, nil, errZ)
		return
	}

	var errA error
	passwordPattern, errA := regexp.Compile ("[a-z0-9]{32,32}$")
	if errA != nil {
		initReport = err.New ("Password pattern regular expression compilation failed.", nil, nil, errA)
		return
	}
}
