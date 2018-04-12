package envelope

import (
	. "github.com/beevik/etree"
)

// When parsing to the WinRM request
type EnvelopeWriter struct {
	Ω      *Document
	π      *Element
	header *EnvelopeHeaderWriter
	body   *EnvelopeBodyWriter
}

func Build() *EnvelopeWriter {
	doc := NewDocument()
	π := doc.CreateElement("s:Envelope")
	π.CreateAttr("xmlns:s", "http://www.w3.org/2003/05/soap-envelope")

	ret := &EnvelopeWriter{
		Ω: doc,
		π: π,
	}

	ret.header = &EnvelopeHeaderWriter{
		envelope: ret,
		π:        ret.createChildElementFor(ret.π, "Header", ns_s),
	}

	ret.body = &EnvelopeBodyWriter{
		envelope: ret,
		π:        ret.createChildElementFor(ret.π, "Body", ns_s),
	}

	return ret
}

type ns_enum uint32

const (
	ns_s   ns_enum = iota
	ns_a
	ns_b
	ns_n
	ns_x
	ns_w
	ns_p
	ns_xsd
	ns_xsi
	ns_rsp
	ns_f
	ns_cfg
)

func (e *EnvelopeWriter) createChildElementFor(target *Element, tag string, ns ns_enum) (ele *Element) {
	var nsKey, nsValue string
	switch ns {
	case ns_s:
		nsKey = "s"
		nsValue = "http://www.w3.org/2003/05/soap-envelope"
	case ns_a:
		nsKey = "a"
		nsValue = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
	case ns_b:
		nsKey = "b"
		nsValue = "http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd"
	case ns_n:
		nsKey = "n"
		nsValue = "http://schemas.xmlsoap.org/ws/2004/09/enumeration"
	case ns_x:
		nsKey = "x"
		nsValue = "http://schemas.xmlsoap.org/ws/2004/09/transfer"
	case ns_w:
		nsKey = "w"
		nsValue = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
	case ns_p:
		nsKey = "p"
		nsValue = "http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"
	case ns_xsd:
		nsKey = "xsd"
		nsValue = "http://www.w3.org/2001/XMLSchema"
	case ns_xsi:
		nsKey = "xsi"
		nsValue = "http://www.w3.org/2001/XMLSchema-instance"
	case ns_rsp:
		nsKey = "rsp"
		nsValue = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
	case ns_f:
		nsKey = "f"
		nsValue = "http://schemas.microsoft.com/wbem/wsman/1/wsmanfault"
	case ns_cfg:
		nsKey = "cfg"
		nsValue = "http://schemas.microsoft.com/wbem/wsman/1/config"
	}

	ele = target.CreateElement(nsKey + ":" + tag)
	e.π.CreateAttr("xmlns:"+nsKey, nsValue)
	return ele
}

func (e *EnvelopeWriter) addMUAttrTo(target *Element, attrVal string) {
	target.CreateAttr("s:mustUnderstand", attrVal)
}

func (e *EnvelopeWriter) addAttrTo(target *Element, attrKey, attrVal string, ns ns_enum) {
	var nsKey, nsValue string
	switch ns {
	case ns_s:
		nsKey = "s"
		nsValue = "http://www.w3.org/2003/05/soap-envelope"
	case ns_a:
		nsKey = "a"
		nsValue = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
	case ns_b:
		nsKey = "b"
		nsValue = "http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd"
	case ns_n:
		nsKey = "n"
		nsValue = "http://schemas.xmlsoap.org/ws/2004/09/enumeration"
	case ns_x:
		nsKey = "x"
		nsValue = "http://schemas.xmlsoap.org/ws/2004/09/transfer"
	case ns_w:
		nsKey = "w"
		nsValue = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
	case ns_p:
		nsKey = "p"
		nsValue = "http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"
	case ns_xsd:
		nsKey = "xsd"
		nsValue = "http://www.w3.org/2001/XMLSchema"
	case ns_xsi:
		nsKey = "xsi"
		nsValue = "http://www.w3.org/2001/XMLSchema-instance"
	case ns_rsp:
		nsKey = "rsp"
		nsValue = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
	case ns_f:
		nsKey = "f"
		nsValue = "http://schemas.microsoft.com/wbem/wsman/1/wsmanfault"
	case ns_cfg:
		nsKey = "cfg"
		nsValue = "http://schemas.microsoft.com/wbem/wsman/1/config"
	}

	target.CreateAttr(nsKey+":"+attrKey, attrVal)
	e.π.CreateAttr("xmlns:"+nsKey, nsValue)
}

func (e *EnvelopeWriter) Header() *EnvelopeHeaderWriter {
	return e.header
}

func (e *EnvelopeWriter) Body() *EnvelopeBodyWriter {
	return e.body
}

func (e *EnvelopeWriter) ToString() (string, error) {
	return e.Ω.WriteToString()
}

func (e *EnvelopeWriter) ToBytes() ([]byte, error) {
	return e.Ω.WriteToBytes()
}
