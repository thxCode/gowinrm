package envelope

import (
	. "github.com/beevik/etree"
)

type SignalResponseEnvelopeBodyReader struct {
	π *Element
}

func (br *SignalResponseEnvelopeBodyReader) GetXMLElement() *Element {
	return br.π
}
