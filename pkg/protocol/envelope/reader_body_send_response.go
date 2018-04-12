package envelope

import (
	. "github.com/beevik/etree"
)

type SendResponseEnvelopeBodyReader struct {
	π *Element
}

func (br *SendResponseEnvelopeBodyReader) GetXMLElement() *Element {
	return br.π
}
