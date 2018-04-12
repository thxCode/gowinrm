package envelope

import (
	"strconv"
	"strings"

	. "github.com/beevik/etree"
)

type EnvelopeHeaderReader struct {
	π *Element
}

func (h *EnvelopeHeaderReader) To() string {
	return strings.TrimSpace(h.π.SelectElement("To").Text())
}

func (h *EnvelopeHeaderReader) ResourceURI() string {
	return strings.TrimSpace(h.π.SelectElement("ResourceURI").Text())
}

func (h *EnvelopeHeaderReader) ReplyTo() string {
	return strings.TrimSpace(h.π.FindElement("//ReplyTo/Address").Text())
}

func (h *EnvelopeHeaderReader) Action() string {
	return strings.TrimSpace(h.π.SelectElement("Action").Text())
}

func (h *EnvelopeHeaderReader) MaxEnvelopeSize() uint64 {
	maxEnvelopeSize := strings.TrimSpace(h.π.SelectElement("MaxEnvelopeSize").Text())
	ret, _ := strconv.ParseUint(maxEnvelopeSize, 10, 64)
	return ret
}

func (h *EnvelopeHeaderReader) MessageID() string {
	return strings.TrimSpace(h.π.SelectElement("MessageID").Text())
}

func (h *EnvelopeHeaderReader) Locale() string {
	return strings.TrimSpace(h.π.SelectElement("Locale").SelectAttr("lang").Value)
}

func (h *EnvelopeHeaderReader) SelectorSet() map[string]string {
	selectorSet := h.π.FindElements("//SelectorSet/Selector")
	ret := make(map[string]string, len(selectorSet))
	for _, selector := range selectorSet {
		key := selector.SelectAttr("Name").Value
		val := strings.TrimSpace(selector.Text())

		ret[key] = val
	}

	return ret
}

func (h *EnvelopeHeaderReader) OperationTimeout() uint64 {
	strs := operationTimeoutReg.FindStringSubmatch(strings.TrimSpace(h.π.SelectElement("OperationTimeout").Text()))
	if len(strs) != 2 {
		return 0
	}

	ret, _ := strconv.ParseUint(strs[1], 10, 64)
	return ret
}

func (h *EnvelopeHeaderReader) RelatesTo() string {
	if h.π == nil {
		return ""
	}

	return strings.TrimSpace(h.π.SelectElement("RelatesTo").Text())
}

func (h *EnvelopeHeaderReader) GetXMLElement() *Element {
	return h.π
}

