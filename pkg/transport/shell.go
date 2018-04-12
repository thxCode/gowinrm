package transport

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/thxcode/gowinrm/pkg/protocol"
	"github.com/thxcode/gowinrm/pkg/protocol/envelope"

	log "github.com/sirupsen/logrus"
)

const (
	replayTo    = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
	resourceURI = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd"
)

type Shell struct {
	ssp            SSP
	sessionId      string
	id             string
	requestTimeOut time.Duration
	// The WS-Management specification defines the MaxEnvelopeSize value to indicate that the clients expect a response to be no larger than the given number of octets
	maxEnvelopeSize uint64
	// The WS-Management specification defines the OperationTimeout value to indicate that the clients expect a response or a fault within the specified time
	operationTimeout uint64
	// A simple token list of all input streams the client will be using during execution. The only supported stream is "stdin".
	// There is no requirement that the client make use of it.
	// However, the client MUST NOT later attempt to send a named stream "stdin" if it is not specified in the wst:Create message.
	// For example, if the client knows that "stdin" will not be used during the session, the client can specify an empty rsp:InputStreams element or omit it entirely.
	// However, if the client anticipates that the "stdin" stream may be used, it MUST include the name in the list. If it is specified, there is no requirement that the client actually use it during the session.
	inputStreams []string
	// A simple token list of all output streams expected by the client. The supported streams are "stdout" and "stderr".
	// There is no requirement that the client make all of them available output streams.
	// For example, if the client only needs "stdout" during the session, it can list "stdout" as the sole stream of interest.
	// If a stream is specified, there is no requirement that the client actually use it during the session.
	outputStreams []string
	// An xs:string value that MUST contain the starting directory that the Shell should use for initialization.
	workingDirectory string
	// EnvironmentVariable extends the xs:string type to describe individual environment variables that may be set when the new Shell is initialized.
	envVars map[string]string
	// If set to TRUE, this option specifies that the user profile does not exist on the remote system and that the default profile SHOULD be used.
	// By default, the value is TRUE.
	noProfile bool
	// The value of the options specifies the client's console output code page.
	// The value is returned by GetConsoleOutputCP API; on the server side, this value is set as input and output code page to display the number of the active character set (code page) or to change the active character set.
	codePage uint32
	// An optional quota setting that configures the maximum time, in seconds, that the Remote Shell will stay open.
	// The time interval is measured beginning from the time that the service receives a wst:Create request for a Remote Shell.
	// The maximum allowed value MUST be 0x7FFFFFFF. The minimum allowed value MUST be 0.
	// This configuration setting is used by the Shell Lifetime timer
	lifetime uint64
	// An optional idle time-out for the Shell.
	// The value MUST be expressed in milliseconds.
	// The service SHOULD close and terminate the command instance if it is idle for this much time.
	// If the Shell is reused within this time limit, the countdown timer is reset once the command sequence is completed
	idleTimeout uint64
	// The client-side mode for standard input is console if TRUE and pipe if FALSE. This does not have an impact on the wire protocol.
	// This option name MUST be used by the client of the Text-based Interactive Shell when starting the execution of a command using rsp:Interactive request to indicate that the client side of the standard input is console; the default implies pipe.
	consoleModeStdin bool
	// If set to TRUE, this option requests that the server runs the command without using cmd.exe; if set to FALSE, the server is requested to use cmd.exe. By default the value is FALSE.
	// This does not have any impact on the wire protocol.
	skipCmdShell bool

	locale     string
	dataLocale string
}

func NewShell(sessionId string, ssp SSP) *Shell {
	log.Debug("create a new command command")

	return &Shell{
		ssp:              ssp,
		sessionId:        sessionId,
		requestTimeOut:   60,
		maxEnvelopeSize:  153600,
		operationTimeout: 300,
		inputStreams:     []string{"stdin"},
		outputStreams:    []string{"stdout", "stderr"},
		codePage:         65001,
		idleTimeout:      60,
		consoleModeStdin: true,
		skipCmdShell:     false,
		locale:           "en-US",
		dataLocale:       "en-US",
	}
}

func (s *Shell) Open() error {
	log.Debugln("open command")

	enveloper := envelope.Build()
	header := enveloper.Header()
	header.
		To(s.ssp.GetRemoteEndpointAddress()).
		ReplyTo(replayTo).
		MaxEnvelopeSize(s.maxEnvelopeSize).
		SessionID(s.sessionId).
		MessageID(protocol.NewUUIDWithPrefix()).
		Locale(s.locale).
		DataLocale(s.dataLocale).
		OperationTimeout(s.operationTimeout).
		ResourceURI(resourceURI).
		Action("http://schemas.xmlsoap.org/ws/2004/09/transfer/Create").
		OptionSet(map[string]string{
		"WINRS_NOPROFILE": strings.ToUpper(strconv.FormatBool(s.noProfile)),
		"WINRS_CODEPAGE":  fmt.Sprint(s.codePage),
	})

	bodyShell := enveloper.Body().Shell()
	bodyShell.InputStreams(strings.Join(s.inputStreams, " "))
	bodyShell.OutputStreams(strings.Join(s.outputStreams, " "))
	if s.workingDirectory != "" {
		bodyShell.WorkingDirectory(s.workingDirectory)
	}

	if s.lifetime != 0 {
		bodyShell.LifeTime(s.lifetime)
	}

	if s.idleTimeout != 0 {
		bodyShell.IdleTimeOut(s.idleTimeout)
	}

	if len(s.envVars) != 0 {
		bodyShell.EnvironmentVariables(s.envVars)
	}

	envelopeBytes, err := enveloper.ToBytes()
	if err != nil {
		return &GoWinRMErr{
			Actual: err,
			Msg:    "cannot create the open command request msg",
		}
	}

	if log.GetLevel() > log.WarnLevel {
		log.Infoln("req soap:", *(*string)(unsafe.Pointer(&envelopeBytes)))
	}
	responseBytes, err := s.ssp.Dial(s.requestTimeOut, envelopeBytes)
	if err != nil {
		return &GoWinRMErr{
			Actual: err,
			Msg:    fmt.Sprintf("dial failure: %s", err.Error()),
		}
	}
	if log.GetLevel() > log.WarnLevel {
		log.Infoln("rep soap:", *(*string)(unsafe.Pointer(&responseBytes)))
	}

	reader, err := envelope.Read(bytes.NewReader(responseBytes))
	if err != nil {
		return &GoWinRMErr{
			Actual: err,
			Msg:    "parse response result error",
		}
	}

	selectSet := reader.Body().ResourceCreated().SelectorSet()
	if shellId, ok := selectSet["ShellId"]; !ok {
		return &GoWinRMErr{
			Actual: errors.New("cannot open a new command"),
			Msg:    string(responseBytes),
		}
	} else {
		s.id = shellId
	}

	return nil
}

func (s *Shell) ExecuteResult(command string, arguments ...string) (*ResultCommand, error) {
	log.Debugln("execute command")

	enveloper := envelope.Build()
	header := enveloper.Header()
	header.
		To(s.ssp.GetRemoteEndpointAddress()).
		ReplyTo(replayTo).
		MaxEnvelopeSize(s.maxEnvelopeSize).
		MessageID("uuid:" + protocol.NewUUIDWithPrefix()).
		SessionID(s.sessionId).
		Locale(s.locale).
		DataLocale(s.dataLocale).
		OperationTimeout(s.operationTimeout).
		ResourceURI(resourceURI).
		Action("http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command").
		SelectorSet(map[string]string{"ShellId": s.id}).
		OptionSet(map[string]string{
		"WINRS_CONSOLEMODE_STDIN": strings.ToUpper(strconv.FormatBool(s.consoleModeStdin)),
		"WINRS_SKIP_CMD_SHELL":    strings.ToUpper(strconv.FormatBool(s.skipCmdShell)),
	})

	bodyCommandLine := enveloper.Body().CommandLine()
	bodyCommandLine.Command(command).Arguments(arguments...)

	envelopeBytes, err := enveloper.ToBytes()
	if err != nil {
		return nil, &GoWinRMErr{
			Actual: err,
			Msg:    "cannot create the run command request msg",
		}
	}

	if log.GetLevel() > log.WarnLevel {
		log.Infoln("req soap:", *(*string)(unsafe.Pointer(&envelopeBytes)))
	}
	responseBytes, err := s.ssp.Dial(s.requestTimeOut, envelopeBytes)
	if err != nil {
		return nil, &GoWinRMErr{
			Actual: err,
			Msg:    fmt.Sprintf("dial failure: %s", err.Error()),
		}
	}
	if log.GetLevel() > log.WarnLevel {
		log.Infoln("rep soap:", *(*string)(unsafe.Pointer(&responseBytes)))
	}

	reader, err := envelope.Read(bytes.NewReader(responseBytes))
	if err != nil {
		return nil, &GoWinRMErr{
			Actual: err,
			Msg:    "parse response result error",
		}
	}

	commandId := reader.Body().CommandResponse().CommandId()
	if commandId == "" {
		return nil, &GoWinRMErr{
			Actual: errors.New("cannot execute command"),
			Msg:    string(responseBytes),
		}
	}

	return &ResultCommand{
		id:    commandId,
		shell: s,
	}, nil

}

func (s *Shell) ExecuteInteractive(command string, arguments ...string) (*InteractiveCommand, error) {
	result, err := s.ExecuteResult(command, arguments...)
	if err != nil {
		return nil, err
	}

	return &InteractiveCommand{
		result,
	}, nil
}

func (s *Shell) Close() error {
	log.Debugln("close command")

	messageId := protocol.NewUUIDWithPrefix()

	enveloper := envelope.Build()
	header := enveloper.Header()
	header.
		To(s.ssp.GetRemoteEndpointAddress()).
		ReplyTo(replayTo).
		MaxEnvelopeSize(s.maxEnvelopeSize).
		SessionID(s.sessionId).
		MessageID(messageId).
		Locale(s.locale).
		DataLocale(s.dataLocale).
		OperationTimeout(s.operationTimeout).
		ResourceURI(resourceURI).
		Action("http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete").
		SelectorSet(map[string]string{"ShellId": s.id})

	envelopeBytes, err := enveloper.ToBytes()
	if err != nil {
		return &GoWinRMErr{
			Actual: err,
			Msg:    "cannot create the close command request msg",
		}
	}

	if log.GetLevel() > log.WarnLevel {
		log.Infoln("req soap:", *(*string)(unsafe.Pointer(&envelopeBytes)))
	}
	responseBytes, err := s.ssp.Dial(s.requestTimeOut, envelopeBytes)
	if err != nil {
		return &GoWinRMErr{
			Actual: err,
			Msg:    fmt.Sprintf("dial failure: %s", err.Error()),
		}
	}
	if log.GetLevel() > log.WarnLevel {
		log.Infoln("rep soap:", *(*string)(unsafe.Pointer(&responseBytes)))
	}

	reader, err := envelope.Read(bytes.NewReader(responseBytes))
	if err != nil {
		return &GoWinRMErr{
			Actual: err,
			Msg:    "parse response result error",
		}
	}

	relatesToId := reader.Header().RelatesTo()
	if relatesToId != messageId {
		return &GoWinRMErr{
			Actual: errors.New(fmt.Sprintf("cannot close command %s", s.id)),
			Msg:    string(responseBytes),
		}
	}

	return nil
}

func (s *Shell) Disconnect() error {
	log.Debugln("disconnect command")

	enveloper := envelope.Build()
	header := enveloper.Header()
	header.
		To(s.ssp.GetRemoteEndpointAddress()).
		ReplyTo(replayTo).
		MaxEnvelopeSize(s.maxEnvelopeSize).
		MessageID(protocol.NewUUIDWithPrefix()).
		SessionID(s.sessionId).
		Locale(s.locale).
		DataLocale(s.dataLocale).
		OperationTimeout(s.operationTimeout).
		ResourceURI(resourceURI).
		Action("http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Disconnect").
		SelectorSet(map[string]string{"ShellId": s.id})

	if s.idleTimeout != 0 {
		bodyDisconnect := enveloper.Body().Disconnect()
		bodyDisconnect.IdleTimeOut(s.idleTimeout)
	}

	envelopeBytes, err := enveloper.ToBytes()
	if err != nil {
		return &GoWinRMErr{
			Actual: err,
			Msg:    "cannot create the disconnect command request msg",
		}
	}

	if log.GetLevel() > log.WarnLevel {
		log.Infoln("req soap:", *(*string)(unsafe.Pointer(&envelopeBytes)))
	}
	responseBytes, err := s.ssp.Dial(s.requestTimeOut, envelopeBytes)
	if err != nil {
		return &GoWinRMErr{
			Actual: err,
			Msg:    fmt.Sprintf("dial failure: %s", err.Error()),
		}
	}
	if log.GetLevel() > log.WarnLevel {
		log.Infoln("rep soap:", *(*string)(unsafe.Pointer(&responseBytes)))
	}

	reader, err := envelope.Read(bytes.NewReader(responseBytes))
	if err != nil {
		return &GoWinRMErr{
			Actual: err,
			Msg:    "parse response result error",
		}
	}

	relatesToId := reader.Header().RelatesTo()
	if relatesToId == "" {
		return &GoWinRMErr{
			Actual: errors.New(fmt.Sprintf("cannot disconnect command %s", s.id)),
			Msg:    string(responseBytes),
		}
	}

	s.id = relatesToId

	return nil
}

func (s *Shell) Reconnect() error {
	log.Debugln("reconnect command")

	enveloper := envelope.Build()
	header := enveloper.Header()
	header.
		To(s.ssp.GetRemoteEndpointAddress()).
		ReplyTo(replayTo).
		MaxEnvelopeSize(s.maxEnvelopeSize).
		MessageID(protocol.NewUUIDWithPrefix()).
		SessionID(s.sessionId).
		Locale(s.locale).
		DataLocale(s.dataLocale).
		OperationTimeout(s.operationTimeout).
		ResourceURI(resourceURI).
		Action("http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Reconnect").
		SelectorSet(map[string]string{"ShellId": s.id})

	envelopeBytes, err := enveloper.ToBytes()
	if err != nil {
		return &GoWinRMErr{
			Actual: err,
			Msg:    "cannot create the disconnect command request msg",
		}
	}

	if log.GetLevel() > log.WarnLevel {
		log.Infoln("req soap:", *(*string)(unsafe.Pointer(&envelopeBytes)))
	}
	responseBytes, err := s.ssp.Dial(s.requestTimeOut, envelopeBytes)
	if err != nil {
		return &GoWinRMErr{
			Actual: err,
			Msg:    fmt.Sprintf("dial failure: %s", err.Error()),
		}
	}
	if log.GetLevel() > log.WarnLevel {
		log.Infoln("rep soap:", *(*string)(unsafe.Pointer(&responseBytes)))
	}

	reader, err := envelope.Read(bytes.NewReader(responseBytes))
	if err != nil {
		return &GoWinRMErr{
			Actual: err,
			Msg:    "parse response result error",
		}
	}



	relatesToId := reader.Header().RelatesTo()
	if relatesToId == "" {
		return &GoWinRMErr{
			Actual: errors.New(fmt.Sprintf("cannot disconnect command %s", s.id)),
			Msg:    string(responseBytes),
		}
	}

	s.id = relatesToId

	return nil
}
