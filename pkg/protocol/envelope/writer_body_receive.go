package envelope

import (
	. "github.com/beevik/etree"
)

type ReceiveEnvelopeBodyWriter struct {
	envelope *EnvelopeWriter
	π        *Element
}

func (bs *ReceiveEnvelopeBodyWriter) DesiredStream(commandId string, outputStreams string) *ReceiveEnvelopeBodyWriter {
	desiredStreamEle := bs.π.SelectElement("DesiredStream")
	if desiredStreamEle == nil {
		desiredStreamEle = bs.envelope.createChildElementFor(bs.π, "DesiredStream", ns_rsp)
		desiredStreamEle.CreateAttr("CommandId", commandId)
	}
	desiredStreamEle.SetText(outputStreams)

	return bs
}

func (bs *ReceiveEnvelopeBodyWriter) ToString() (string, error) {
	return bs.envelope.ToString()
}

func (bs *ReceiveEnvelopeBodyWriter) ToBytes() ([]byte, error) {
	return bs.envelope.ToBytes()
}
