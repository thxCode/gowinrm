package envelope

import (
	b64 "encoding/base64"
	"io"
	"strings"

	. "github.com/beevik/etree"
)

type ReceiveResponseEnvelopeBodyReader struct {
	π *Element
}

func (br *ReceiveResponseEnvelopeBodyReader) Stream(outputStreamsMap map[string]io.Writer) error {
	streamEles := br.π.SelectElements("Stream")
	for _, streamEle := range streamEles {
		streamName := streamEle.SelectAttrValue("Name", "unknown")
		content := streamEle.Text()

		if contentBytes, err := b64.StdEncoding.DecodeString(content); err != nil {
			return err
		} else {
			alreadyWroteSize := 0
			contentBytesSize := len(contentBytes)
			streamWriter := outputStreamsMap[streamName]

			for {
				wroteSize, err := streamWriter.Write(contentBytes)
				if err != nil {
					return err
				}
				alreadyWroteSize += wroteSize
				if alreadyWroteSize >= contentBytesSize {
					break
				}
			}
		}
	}

	return nil
}

func (br *ReceiveResponseEnvelopeBodyReader) CommandState() (state, exitCode string) {
	commandStateEle := br.π.SelectElement("CommandState")
	state = commandStateEle.SelectAttrValue("State", "http://schemas.microsoft.com/wbem/wsman/1/windows/command/CommandState/Done")
	stateLastSlashPos := strings.LastIndex(state, "/")
	state = state[stateLastSlashPos+1:]

	exitCodeEle := commandStateEle.SelectElement("ExitCode")
	exitCode = exitCodeEle.Text()

	return state, exitCode
}

func (br *ReceiveResponseEnvelopeBodyReader) GetXMLElement() *Element {
	return br.π
}
