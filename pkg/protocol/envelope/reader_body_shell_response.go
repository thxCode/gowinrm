package envelope

import (
	"strings"

	. "github.com/beevik/etree"
)

type ResourceCreatedEnvelopeBodyReader struct {
	π *Element
}

func (br *ResourceCreatedEnvelopeBodyReader) SelectorSet() map[string]string {
	if br.π == nil {
		return nil
	}

	selectorSetEle := br.π.FindElements("//ReferenceParameters/SelectorSet/Selector")

	ret := make(map[string]string, len(selectorSetEle))
	for _, selectorEle := range selectorSetEle {
		key := selectorEle.SelectAttr("Name").Value
		val := strings.TrimSpace(selectorEle.Text())

		ret[key] = val
	}
	return ret
}

func (br *ResourceCreatedEnvelopeBodyReader) GetXMLElement() *Element {
	return br.π
}