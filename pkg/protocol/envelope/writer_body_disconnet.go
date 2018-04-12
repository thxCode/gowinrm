package envelope

import (
	"fmt"

	. "github.com/beevik/etree"
)

type DisconnectEnvelopeBodyWriter struct {
	envelope *EnvelopeWriter
	π        *Element
}

func (bs *DisconnectEnvelopeBodyWriter) IdleTimeOut(idleTimeout uint64) *DisconnectEnvelopeBodyWriter {
	idleTimeoutEle := bs.π.SelectElement("IdleTimeOut")
	if idleTimeoutEle == nil {
		idleTimeoutEle = bs.envelope.createChildElementFor(bs.π, "IdleTimeOut", ns_rsp)
	}
	idleTimeoutEle.SetText(fmt.Sprintf("PT%dS", idleTimeout))

	return bs
}

func (bs *DisconnectEnvelopeBodyWriter) ToString() (string, error) {
	return bs.envelope.ToString()
}

func (bs *DisconnectEnvelopeBodyWriter) ToBytes() ([]byte, error) {
	return bs.envelope.ToBytes()
}
