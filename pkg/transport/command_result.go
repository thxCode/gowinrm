package transport

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"unsafe"

	"github.com/thxcode/gowinrm/pkg/protocol"
	"github.com/thxcode/gowinrm/pkg/protocol/envelope"

	log "github.com/sirupsen/logrus"
)

type ResultCmd struct {
	id    string
	shell *Shell
}

func (c *ResultCmd) Stop() error {
	log.Debugln("terminate command")

	enveloper := envelope.Build()
	header := enveloper.Header()
	header.
		To(c.shell.dialer.GetURL()).
		ReplyTo(replayTo).
		MaxEnvelopeSize(c.shell.maxEnvelopeSize).
		MessageID(protocol.NewUUIDWithPrefix()).
		SessionID(c.shell.sessionId).
		Locale(c.shell.locale).
		DataLocale(c.shell.dataLocale).
		OperationTimeout(c.shell.operationTimeout).
		ResourceURI(resourceURI).
		Action("http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal").
		SelectorSet(map[string]string{"ShellId": c.shell.id})

	bodySignal := enveloper.Body().Signal(c.id)
	bodySignal.Code("http://schemas.microsoft.com/wbem/wsman/1/windows/command/signal/ctrl_c")

	envelopeBytes, err := enveloper.ToBytes()
	if err != nil {
		return &GoWinRMErr{
			Actual: err,
			Msg:    "cannot create the terminate command request msg",
		}
	}

	responseBytes, err := c.shell.dialer.Dial(c.shell.requestTimeOut, envelopeBytes)
	if err != nil {
		return &GoWinRMErr{
			Actual: err,
			Msg:    fmt.Sprintf("dial failure: %s", err.Error()),
		}
	}

	if log.GetLevel() > log.WarnLevel {
		log.Infoln("req soap:", *(*string)(unsafe.Pointer(&envelopeBytes)))
		log.Infoln("rep soap:", *(*string)(unsafe.Pointer(&responseBytes)))
	}

	_, err = envelope.Read(bytes.NewReader(responseBytes))
	if err != nil {
		return &GoWinRMErr{
			Actual: err,
			Msg:    "parse response result error",
		}
	}

	return nil
}

func (c *ResultCmd) Receive(outputStreamsMap map[string]io.Writer) error {
	log.Debugln("stdout command")

	if len(outputStreamsMap) == 0 {
		return errors.New("outputStreams map cannot be empty")
	} else if len(outputStreamsMap) > 2 {
		return errors.New("outputStreams map only support both \"stdout\" and \"stderr\"")
	} else {
		_, hasStdout := outputStreamsMap["stdout"]
		_, hasStderr := outputStreamsMap["stderr"]
		if !hasStderr && !hasStdout {
			return errors.New("outputStreams map only support \"stdout\" or \"stderr\"")
		}
	}

	messageID := protocol.NewUUIDWithPrefix()
	sequenceId := uint64(0)

	enveloper := envelope.Build()
	header := enveloper.Header()
	header.
		To(c.shell.dialer.GetURL()).
		ReplyTo(replayTo).
		MaxEnvelopeSize(c.shell.maxEnvelopeSize).
		MessageID(messageID).
		SessionID(c.shell.sessionId).
		Locale(c.shell.locale).
		DataLocale(c.shell.dataLocale).
		OperationTimeout(c.shell.operationTimeout).
		ResourceURI(resourceURI).
		Action("http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive").
		SelectorSet(map[string]string{"ShellId": c.shell.id})

	body := enveloper.Body()
	body.Receive(sequenceId).DesiredStream(c.id, strings.Join(c.shell.outputStreams, " "))

	for {
		envelopeBytes, err := enveloper.ToBytes()
		if err != nil {
			return &GoWinRMErr{
				Actual: err,
				Msg:    "cannot create the receive command request msg",
			}
		}

		responseBytes, err := c.shell.dialer.Dial(c.shell.requestTimeOut, envelopeBytes)
		if err != nil {
			return &GoWinRMErr{
				Actual: err,
				Msg:    fmt.Sprintf("dial failure: %s", err.Error()),
			}
		}

		if log.GetLevel() > log.WarnLevel {
			log.Infoln("req soap:", *(*string)(unsafe.Pointer(&envelopeBytes)))
			log.Infoln("rep soap:", *(*string)(unsafe.Pointer(&responseBytes)))
		}

		reader, err := envelope.Read(bytes.NewReader(responseBytes))
		if err != nil {
			return &GoWinRMErr{
				Actual: err,
				Msg:    "parse response result error",
			}
		}

		respMessageID := reader.Header().RelatesTo()
		if respMessageID != messageID {
			continue
		}

		receiveResponse := reader.Body().ReceiveResponse()

		if err := receiveResponse.Stream(outputStreamsMap); err != nil {
			return err
		}

		state, exitCode := receiveResponse.CommandState()
		if state == "Done" {
			if exitCode != "0" {
				return &GoWinRMErr{
					Actual: errors.New("all done, but failure"),
					Msg:    string(responseBytes),
				}
			} else {
				break
			}
		}

		messageID = protocol.NewUUIDWithPrefix()
		header.MessageID(messageID)

		sequenceId += 1
		body.Receive(sequenceId)
	}

	return io.EOF
}

func (c *ResultCmd) Close() error {
	log.Debugln("close command")

	if c != nil {
		c.shell.Close()
	}

	return nil
}
