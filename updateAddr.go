package lib

import (
	"context"
	"database/sql"
	"gopkg.in/qamarian-dtp/err.v0" // v0.4.0
	"net"
	"regexp"
)

func UpdateAddr (addr string, port int, serviceID, password string, dbConn *sql.Conn) (error){
	// Arg 0 (addr) validation. ..1.. {
	if net.ParseIP (addr) == nil {
		return err.New ("Invalid arg 0 (address) provided.", nil, nil)
	}
	// ..1.. }

	// Arg 1 (port) validation. ..1.. {
	if port < 0 || port > 65535 {
		return err.New ("Invalid arg 1 (port) provided.", nil, nil)
	}
	// ..1.. }

	// Arg 2 (serviceID) validation. ..1.. {
	if ! serviceIDPattern.Match ([]byte (serviceID)) {
		return err.New ("Invalid arg 2 (service ID) provided.", nil, nil)
	}
	// ..1.. }

	// Arg 3 (password) validation. ..1.. {
	if ! passwordPattern.Match ([]byte (password)) {
		return err.New ("Invalid arg 3 (password) provided.", nil, nil)
	}
	// ..1.. }

	// Arg 4 (dbConn) validation. ..1.. {
	if dbConn == nil {
		return err.New ("Nil arg 4 (database connection) provided.", nil, nil)
	}
	// ..1.. }

	// SQL instructions definitions. ..1.. {
	instructionX := `SELECT record_id
	FROM service_addr
	WHERE service_id = ?`

	instructionY := `SELECT record_id
	FROM service_addr
	WHERE service_id = ? AND pass = ?`

	instructionZ := `UPDATE service_addr
	SET addr = ?, port = ?
	WHERE service_id = ? AND pass = ?`
	// ..1.. }

	// Validating existence of service. ..1.. {
	var uselessX string
	errY := dbConn.QueryRowContext (context.Background (), instructionX,
		serviceID).Scan (&uselessX)
	if errY != nil && errY == sql.ErrNoRows {
		return err.New ("Service does not exist.", nil, nil)
	}
	if errY != nil {
		return err.New ("Unable to verify existence of service.", nil, nil, errY)
	}
	// ..1.. }

	// Validating correctness of service password. ..1.. {
	var uselessY string
	errZ := dbConn.QueryRowContext (context.Background (), instructionY, serviceID,
		password).Scan (&uselessY)
	if errZ != nil && errZ == sql.ErrNoRows {
		return err.New ("Invalid password.", nil, nil)
	}
	if errZ != nil {
		return err.New ("Unable to verify validity of password.", nil, nil, errZ)
	}
	// ..1.. }

	// Updating network address. ..1.. {
	_, errA := dbConn.ExecContext (context.Background (), instructionZ, addr, port,
		serviceID, password)
	if errA != nil {
		return err.New ("Unable to update service address.", nil, nil, errA)
	}
	// ..1.. }

	return nil
}

var (
	serviceIDPattern *regexp.Regexp
	passwordPattern *regexp.Regexp
)

func init () {
	if initReport != nil {
		return
	}

	var errZ error
	serviceIDPattern, errZ = regexp.Compile ("^[a-z0-9]{1,2}$")
	if errZ != nil {
		initReport = err.New ("Service ID pattern regular expression " +
			"compilation failed.", nil, nil, errZ)
		return
	}

	var errA error
	passwordPattern, errA = regexp.Compile ("^[a-z0-9]{32,32}$")
	if errA != nil {
		initReport = err.New ("Password pattern regular expression compilation " +
			"failed.", nil, nil, errA)
		return
	}
}
