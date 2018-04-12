package envelope

import (
	"strings"

	. "github.com/beevik/etree"
)

type CommandResponseEnvelopeBodyReader struct {
	π *Element
}

func (br *CommandResponseEnvelopeBodyReader) CommandId() string {
	if br.π == nil {
		return ""
	}

	commandIdEle := br.π.SelectElement("CommandId")

	return strings.TrimSpace(commandIdEle.Text())
}

func (br *CommandResponseEnvelopeBodyReader) GetXMLElement() *Element {
	return br.π
}
