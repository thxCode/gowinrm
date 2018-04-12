package envelope

import (
	. "github.com/beevik/etree"
)

type SendEnvelopeBodyWriter struct {
	envelope *EnvelopeWriter
	π        *Element
}

func (bs *SendEnvelopeBodyWriter) Stream(streamName, commandId, inputStream string) *SendEnvelopeBodyWriter {
	streamEle := bs.π.SelectElement("Stream")
	if streamEle == nil {
		streamEle = bs.envelope.createChildElementFor(bs.π, "Stream", ns_rsp)
		streamEle.CreateAttr("CommandId", commandId)
		streamEle.CreateAttr("Name", streamName)
	}
	streamEle.SetText(inputStream)

	return bs
}

func (bs *SendEnvelopeBodyWriter) ToString() (string, error) {
	return bs.envelope.ToString()
}

func (bs *SendEnvelopeBodyWriter) ToBytes() ([]byte, error) {
	return bs.envelope.ToBytes()
}
