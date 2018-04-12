package gowinrm

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/thxcode/gowinrm/pkg/protocol"
	"github.com/thxcode/gowinrm/pkg/transport"
)

type ShellType uint32

const (
	Command    ShellType = iota
	PowerShell
)

type Session struct {
	// This is a unique identifier for a client session, which is a set of related operations against a server.
	id string

	dialer transport.Dialer
}

func NewSession(dialer transport.Dialer) *Session {
	ret := &Session{
		id:     protocol.NewUUIDWithPrefix(),
		dialer: dialer,
	}

	return ret
}

func (s *Session) Close() error {
	if s != nil {
		s.dialer.Close()
	}

	return nil
}

func ToUTF16le(cmdExpression string, arguments ...string) string {
	stub := []byte("\x00")
	sb := &strings.Builder{}

	for _, b := range []byte(cmdExpression + " " + strings.Join(arguments, " ")) {
		sb.Write([]byte{b})
		sb.Write(stub)
	}

	// Base64 encode the command
	input := []uint8(sb.String())
	return base64.StdEncoding.EncodeToString(input)
}

func (s *Session) NewInteractiveCommand(shellType ShellType, cmdExpression string, arguments ...string) (*transport.InteractiveCmd, error) {
	sh := transport.NewShell(s.id, s.dialer)
	err := sh.Open()
	if err != nil {
		return nil, err
	}

	switch shellType {
	case PowerShell:
		cmdExpression = fmt.Sprintf("powershell -encodedCommand %s", ToUTF16le(cmdExpression, arguments...))
		arguments = []string{}
		fallthrough
	case Command:
		cmd, err := sh.ExecuteInteractive(cmdExpression, arguments...)
		if err != nil {
			return nil, err
		}

		return cmd, nil
	}

	return nil, errors.New("invalid command type")
}

func (s *Session) NewResultCommand(shellType ShellType, cmdExpression string, arguments ...string) (*transport.ResultCmd, error) {
	sh := transport.NewShell(s.id, s.dialer)
	err := sh.Open()
	if err != nil {
		return nil, err
	}

	switch shellType {
	case PowerShell:
		cmdExpression = fmt.Sprintf("powershell -encodedCommand %s", ToUTF16le(cmdExpression, arguments...))
		arguments = []string{}
		fallthrough
	case Command:
		cmd, err := sh.ExecuteResult(cmdExpression, arguments...)
		if err != nil {
			return nil, err
		}

		return cmd, nil
	}

	return nil, errors.New("invalid command type")
}
