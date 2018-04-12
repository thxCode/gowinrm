package envelope

import (
	"strings"

	. "github.com/beevik/etree"
)

type CommandLineEnvelopeBodyWriter struct {
	envelope *EnvelopeWriter
	π        *Element
}

func (bs *CommandLineEnvelopeBodyWriter) Command(command string) *CommandLineEnvelopeBodyWriter {
	commandEle := bs.π.SelectElement("Command")
	if commandEle == nil {
		commandEle = bs.envelope.createChildElementFor(bs.π, "Command", ns_rsp)
	}
	commandEle.CreateCharData(command)

	return bs
}

func (bs *CommandLineEnvelopeBodyWriter) Arguments(arguments ...string) *CommandLineEnvelopeBodyWriter {
	if len(arguments) == 0 {
		return bs
	}

	argumentsEle := bs.π.SelectElement("Arguments")
	if argumentsEle == nil {
		argumentsEle = bs.envelope.createChildElementFor(bs.π, "Arguments", ns_rsp)
	}
	argumentsEle.CreateCharData(strings.Join(arguments, " "))

	return bs
}

func (bs *CommandLineEnvelopeBodyWriter) ToString() (string, error) {
	return bs.envelope.ToString()
}

func (bs *CommandLineEnvelopeBodyWriter) ToBytes() ([]byte, error) {
	return bs.envelope.ToBytes()
}
