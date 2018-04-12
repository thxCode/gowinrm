package envelope

import (
	. "github.com/beevik/etree"
)

type SignalEnvelopeBodyWriter struct {
	envelope *EnvelopeWriter
	π        *Element
}

func (bs *SignalEnvelopeBodyWriter) Code(code string) *SignalEnvelopeBodyWriter {
	codeEle := bs.π.SelectElement("Code")
	if codeEle == nil {
		codeEle = bs.envelope.createChildElementFor(bs.π, "Code", ns_rsp)
	}
	codeEle.SetText(code)

	return bs
}

func (bs *SignalEnvelopeBodyWriter) ToString() (string, error) {
	return bs.envelope.ToString()
}

func (bs *SignalEnvelopeBodyWriter) ToBytes() ([]byte, error) {
	return bs.envelope.ToBytes()
}
