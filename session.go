package gowinrm

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
	"unicode/utf8"
	"unsafe"

	"github.com/thxcode/gowinrm/pkg/protocol"
	"github.com/thxcode/gowinrm/pkg/transport"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

type ShellType uint32

const (
	Command    ShellType = iota
	PowerShell
)

var (
	UTF16LeEncoder = unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
)

type Session struct {
	// This is a unique identifier for a client session, which is a set of related operations against a server.
	id string

	ssp transport.SSP
}

func NewSession(ssp transport.SSP) *Session {
	ret := &Session{
		id:  protocol.NewUUIDWithPrefix(),
		ssp: ssp,
	}

	return ret
}

func (s *Session) Close() error {
	if s != nil {
		s.ssp.Close()
	}

	return nil
}

func toUTF16le(cmdExpression string, arguments ...string) (string, error) {
	source := cmdExpression + " " + strings.Join(arguments, " ")
	if !utf8.ValidString(source) {
		return "", encoding.ErrInvalidUTF8
	}

	sourceReader := bytes.NewReader([]byte(source))
	transformReader := transform.NewReader(sourceReader, UTF16LeEncoder)

	result, err := ioutil.ReadAll(transformReader)
	if err != nil {
		return "", err
	}

	return *(*string)(unsafe.Pointer(&result)), nil
}

func (s *Session) NewInteractiveCommand(shellType ShellType, cmdExpression string, arguments ...string) (*transport.InteractiveCommand, error) {
	sh := transport.NewShell(s.id, s.ssp)
	err := sh.Open()
	if err != nil {
		return nil, err
	}

	switch shellType {
	case PowerShell:
		cmdExpression, err := toUTF16le(cmdExpression, arguments...)
		if err != nil {
			return nil, err
		}

		cmdExpression = fmt.Sprintf("powershell -encodedCommand %s", cmdExpression)
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

func (s *Session) NewResultCommand(shellType ShellType, cmdExpression string, arguments ...string) (*transport.ResultCommand, error) {
	sh := transport.NewShell(s.id, s.ssp)
	err := sh.Open()
	if err != nil {
		return nil, err
	}

	switch shellType {
	case PowerShell:
		cmdExpression, err := toUTF16le(cmdExpression, arguments...)
		if err != nil {
			return nil, err
		}

		cmdExpression = fmt.Sprintf("powershell -encodedCommand %s", cmdExpression)
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
