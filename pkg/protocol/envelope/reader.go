package envelope

import (
	"io"
	"regexp"

	. "github.com/beevik/etree"
)

var operationTimeoutReg = regexp.MustCompile("PT(.*)S")

// When parsing from the WinRM response
type EnvelopeReader struct {
	Ω      *Document
	π      *Element
	header *EnvelopeHeaderReader
	body   *EnvelopeBodyReader
}

func Read(envelopeXML io.Reader) (*EnvelopeReader, error) {
	doc := NewDocument()
	if _, err := doc.ReadFrom(envelopeXML); err != nil {
		return nil, err
	}
	π := doc.Root()

	return &EnvelopeReader{
		Ω: doc,
		π: π,
		header: &EnvelopeHeaderReader{
			π.SelectElement("Header"),
		},
		body: &EnvelopeBodyReader{
			π.SelectElement("Body"),
		},
	}, nil
}

func (e *EnvelopeReader) Header() *EnvelopeHeaderReader {
	return e.header
}

func (e *EnvelopeReader) Body() *EnvelopeBodyReader {
	return e.body
}

func (e *EnvelopeReader) GetXMLElement() *Element {
	return e.π
}
