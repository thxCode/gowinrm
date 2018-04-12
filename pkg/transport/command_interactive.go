package transport

import (
	"bytes"
	b64 "encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"unsafe"

	"github.com/thxcode/gowinrm/pkg/protocol"
	"github.com/thxcode/gowinrm/pkg/protocol/envelope"

	log "github.com/sirupsen/logrus"
)

type InteractiveCommand struct {
	*ResultCommand
}

func (c *InteractiveCommand) Send(inputStreamMap map[string]io.Reader) error {
	log.Debugln("stdout command")

	if len(inputStreamMap) == 0 {
		return errors.New("inputStreamMap map cannot be empty")
	}
	if _, ok := inputStreamMap["stdin"]; !ok {
		return errors.New("inputStreamMap map only support \"stdin\" stream")
	}

	messageID := protocol.NewUUIDWithPrefix()

	enveloper := envelope.Build()
	header := enveloper.Header()
	header.
		To(c.shell.ssp.GetRemoteEndpointAddress()).
		ReplyTo(replayTo).
		MaxEnvelopeSize(c.shell.maxEnvelopeSize).
		MessageID(messageID).
		SessionID(c.shell.sessionId).
		Locale(c.shell.locale).
		DataLocale(c.shell.dataLocale).
		OperationTimeout(c.shell.operationTimeout).
		ResourceURI(resourceURI).
		Action("http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send").
		SelectorSet(map[string]string{"ShellId": c.shell.id})

	bodySender := enveloper.Body().Send()

	streamName := strings.Join(c.shell.inputStreams, " ")
	stdin := inputStreamMap["stdin"]

	for {
		var bs [1 << 20]byte
		readSize, err := stdin.Read(bs[:])
		if readSize == 0 || err != nil {
			if err != io.EOF {
				return err
			}
			return nil
		}

		inputStream := b64.StdEncoding.EncodeToString(bs[:])
		bodySender.Stream(streamName, c.id, inputStream)

		envelopeBytes, err := enveloper.ToBytes()
		if err != nil {
			return &GoWinRMErr{
				Actual: err,
				Msg:    "cannot create the send command request msg",
			}
		}

		responseBytes, err := c.shell.ssp.Dial(c.shell.requestTimeOut, envelopeBytes)
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
	}

}
