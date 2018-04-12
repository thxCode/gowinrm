package envelope

import (
	"fmt"
	"strconv"

	. "github.com/beevik/etree"
)

type EnvelopeHeaderWriter struct {
	envelope *EnvelopeWriter
	π        *Element
}

func (h *EnvelopeHeaderWriter) To(to string) *EnvelopeHeaderWriter {
	toEle := h.π.SelectElement("To")
	if toEle == nil {
		toEle = h.envelope.createChildElementFor(h.π, "To", ns_a)
	}
	toEle.SetText(to)

	return h
}

func (h *EnvelopeHeaderWriter) ResourceURI(uri string) *EnvelopeHeaderWriter {
	resourceURIEle := h.π.SelectElement("ResourceURI")
	if resourceURIEle == nil {
		resourceURIEle = h.envelope.createChildElementFor(h.π, "ResourceURI", ns_w)
		h.envelope.addMUAttrTo(resourceURIEle, "true")
	}
	resourceURIEle.SetText(uri)

	return h
}

func (h *EnvelopeHeaderWriter) ReplyTo(address string) *EnvelopeHeaderWriter {
	addressEle := h.π.FindElement("//ReplyTo/Address")
	if addressEle == nil {
		// h.envelope.createChildElementFor(h.envelope.createChildElementFor(h.π, "ReplyTo", ns_a), "Address", ns_a)
		addressEle = h.envelope.createChildElementFor(h.π, "ReplyTo", ns_a).CreateElement("a:Address")
		h.envelope.addMUAttrTo(addressEle, "true")
	}
	addressEle.SetText(address)

	return h
}

func (h *EnvelopeHeaderWriter) Action(action string) *EnvelopeHeaderWriter {
	actionEle := h.π.SelectElement("Action")
	if actionEle == nil {
		actionEle = h.envelope.createChildElementFor(h.π, "Action", ns_a)
		h.envelope.addMUAttrTo(actionEle, "true")
	}
	actionEle.SetText(action)

	return h
}

func (h *EnvelopeHeaderWriter) MaxEnvelopeSize(maxEnvelopeSize uint64) *EnvelopeHeaderWriter {
	maxEnvelopeSizeEle := h.π.SelectElement("MaxEnvelopeSize")
	if maxEnvelopeSizeEle == nil {
		maxEnvelopeSizeEle = h.envelope.createChildElementFor(h.π, "MaxEnvelopeSize", ns_w)
		h.envelope.addMUAttrTo(maxEnvelopeSizeEle, "true")
	}
	maxEnvelopeSizeEle.SetText(strconv.FormatUint(maxEnvelopeSize, 10))

	return h
}

func (h *EnvelopeHeaderWriter) MessageID(messageID string) *EnvelopeHeaderWriter {
	messageIDEle := h.π.SelectElement("MessageID")
	if messageIDEle == nil {
		messageIDEle = h.envelope.createChildElementFor(h.π, "MessageID", ns_a)
	}
	messageIDEle.SetText(messageID)

	return h
}

func (h *EnvelopeHeaderWriter) SessionID(sessionID string) *EnvelopeHeaderWriter {
	sessionIDEle := h.π.SelectElement("SessionID")
	if sessionIDEle == nil {
		sessionIDEle = h.envelope.createChildElementFor(h.π, "SessionID", ns_p)
	}
	sessionIDEle.SetText(sessionID)

	return h
}

func (h *EnvelopeHeaderWriter) Locale(locale string) *EnvelopeHeaderWriter {
	localeEle := h.π.SelectElement("Locale")
	if localeEle == nil {
		localeEle = h.envelope.createChildElementFor(h.π, "Locale", ns_w)
		h.envelope.addMUAttrTo(localeEle, "false")
		localeEle.CreateAttr("xml:lang", locale)
	} else {
		localeEle.SelectAttr("xml:lang").Value = locale
	}

	return h
}

func (h *EnvelopeHeaderWriter) DataLocale(dataLocale string) *EnvelopeHeaderWriter {
	localeEle := h.π.SelectElement("DataLocale")
	if localeEle == nil {
		localeEle = h.envelope.createChildElementFor(h.π, "DataLocale", ns_p)
		h.envelope.addMUAttrTo(localeEle, "false")
		localeEle.CreateAttr("xml:lang", dataLocale)
	} else {
		localeEle.SelectAttr("xml:lang").Value = dataLocale
	}

	return h
}

func (h *EnvelopeHeaderWriter) SelectorSet(selectSet map[string]string) *EnvelopeHeaderWriter {
	selectorSetEle := h.π.SelectElement("SelectorSet")
	if selectorSetEle != nil {
		h.π.RemoveChild(selectorSetEle)
	}

	selectorSetEle = h.envelope.createChildElementFor(h.π, "SelectorSet", ns_w)

	for k, v := range selectSet {
		// h.envelope.createChildElementFor(selectorSetEle, "Selector", ns_w)
		selectorEle := selectorSetEle.CreateElement("w:Selector")
		selectorEle.CreateAttr("Name", k)
		selectorEle.SetText(v)
	}

	return h
}

func (h *EnvelopeHeaderWriter) OptionSet(optionSet map[string]string) *EnvelopeHeaderWriter {
	optionSetEle := h.π.SelectElement("OptionSet")
	if optionSetEle != nil {
		h.π.RemoveChild(optionSetEle)
	}

	optionSetEle = h.envelope.createChildElementFor(h.π, "OptionSet", ns_w)

	for k, v := range optionSet {
		// h.envelope.createChildElementFor(optionSetEle, "Option", ns_w)
		optionEle := optionSetEle.CreateElement("w:Option")
		optionEle.CreateAttr("Name", k)
		optionEle.SetText(v)
	}

	return h
}

func (h *EnvelopeHeaderWriter) OperationTimeout(operationTimeoutSeconds uint64) *EnvelopeHeaderWriter {
	operationTimeoutEle := h.π.SelectElement("OperationTimeout")
	if operationTimeoutEle == nil {
		operationTimeoutEle = h.envelope.createChildElementFor(h.π, "OperationTimeout", ns_w)
	}
	operationTimeoutEle.SetText(fmt.Sprintf("PT%dS", operationTimeoutSeconds))

	return h
}

func (h *EnvelopeHeaderWriter) Body() *EnvelopeBodyWriter {
	return h.envelope.body
}

func (h *EnvelopeHeaderWriter) ToString() (string, error) {
	return h.envelope.ToString()
}

func (h *EnvelopeHeaderWriter) ToBytes() ([]byte, error) {
	return h.envelope.ToBytes()
}
