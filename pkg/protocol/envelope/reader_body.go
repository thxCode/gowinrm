package envelope

import (
	. "github.com/beevik/etree"
)

type EnvelopeBodyReader struct {
	π *Element
}

func (br *EnvelopeBodyReader) ResourceCreated() *ResourceCreatedEnvelopeBodyReader {
	return &ResourceCreatedEnvelopeBodyReader{
		π: br.π.SelectElement("ResourceCreated"),
	}
}

func (br *EnvelopeBodyReader) CommandResponse() *CommandResponseEnvelopeBodyReader {
	return &CommandResponseEnvelopeBodyReader{
		π: br.π.SelectElement("CommandResponse"),
	}
}

func (br *EnvelopeBodyReader) SignalResponse() *SignalResponseEnvelopeBodyReader {
	return &SignalResponseEnvelopeBodyReader{
		π: br.π.SelectElement("SignalResponse"),
	}
}

func (br *EnvelopeBodyReader) ReceiveResponse() *ReceiveResponseEnvelopeBodyReader {
	return &ReceiveResponseEnvelopeBodyReader{
		π: br.π.SelectElement("ReceiveResponse"),
	}
}

func (br *EnvelopeBodyReader) SendResponse() *SendResponseEnvelopeBodyReader {
	return &SendResponseEnvelopeBodyReader{
		π: br.π.SelectElement("SendResponse"),
	}
}

func (br *EnvelopeBodyReader) GetXMLElement() *Element {
	return br.π
}
