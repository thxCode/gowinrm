package envelope

import (
	"fmt"

	. "github.com/beevik/etree"
)

type EnvelopeBodyWriter struct {
	envelope *EnvelopeWriter
	π        *Element
}

func (b *EnvelopeBodyWriter) Shell() *ShellEnvelopeBodyWriter {
	shellEle := b.π.SelectElement("Shell")
	if shellEle != nil {
		return &ShellEnvelopeBodyWriter{
			envelope: b.envelope,
			π:        shellEle,
		}
	}

	return &ShellEnvelopeBodyWriter{
		envelope: b.envelope,
		π:        b.envelope.createChildElementFor(b.π, "Shell", ns_rsp),
	}
}

func (b *EnvelopeBodyWriter) CommandLine() *CommandLineEnvelopeBodyWriter {
	commandLineEle := b.π.SelectElement("CommandLine")
	if commandLineEle != nil {
		return &CommandLineEnvelopeBodyWriter{
			envelope: b.envelope,
			π:        commandLineEle,
		}
	}

	return &CommandLineEnvelopeBodyWriter{
		envelope: b.envelope,
		π:        b.envelope.createChildElementFor(b.π, "CommandLine", ns_rsp),
	}
}

func (b *EnvelopeBodyWriter) Disconnect() *DisconnectEnvelopeBodyWriter {
	disconnectEle := b.π.SelectElement("Disconnect")
	if disconnectEle != nil {
		return &DisconnectEnvelopeBodyWriter{
			envelope: b.envelope,
			π:        disconnectEle,
		}
	}

	return &DisconnectEnvelopeBodyWriter{
		envelope: b.envelope,
		π:        b.envelope.createChildElementFor(b.π, "Disconnect", ns_rsp),
	}
}

func (b *EnvelopeBodyWriter) Signal(commandId string) *SignalEnvelopeBodyWriter {
	signalEle := b.π.SelectElement("Signal")
	if signalEle != nil {
		signalEle.RemoveAttr("CommandId")
		signalEle.CreateAttr("CommandId", commandId)
		return &SignalEnvelopeBodyWriter{
			envelope: b.envelope,
			π:        signalEle,
		}
	}

	signalEle = b.envelope.createChildElementFor(b.π, "Signal", ns_rsp)
	signalEle.CreateAttr("CommandId", commandId)
	return &SignalEnvelopeBodyWriter{
		envelope: b.envelope,
		π:        signalEle,
	}
}

func (b *EnvelopeBodyWriter) Receive(sequenceId uint64) *ReceiveEnvelopeBodyWriter {
	signalEle := b.π.SelectElement("Receive")
	if signalEle != nil {
		signalEle.RemoveAttr("SequenceId")
		signalEle.CreateAttr("SequenceId", fmt.Sprint(sequenceId))
		return &ReceiveEnvelopeBodyWriter{
			envelope: b.envelope,
			π:        signalEle,
		}
	}

	signalEle = b.envelope.createChildElementFor(b.π, "Receive", ns_rsp)
	signalEle.CreateAttr("SequenceId", fmt.Sprint(sequenceId))
	return &ReceiveEnvelopeBodyWriter{
		envelope: b.envelope,
		π:        signalEle,
	}
}

func (b *EnvelopeBodyWriter) Send() *SendEnvelopeBodyWriter {
	sendEle := b.π.SelectElement("Send")
	if sendEle != nil {
		return &SendEnvelopeBodyWriter{
			envelope: b.envelope,
			π:        sendEle,
		}
	}

	return &SendEnvelopeBodyWriter{
		envelope: b.envelope,
		π:        b.envelope.createChildElementFor(b.π, "Send", ns_rsp),
	}

}

func (b *EnvelopeBodyWriter) ToString() (string, error) {
	return b.envelope.ToString()
}

func (b *EnvelopeBodyWriter) ToBytes() ([]byte, error) {
	return b.envelope.ToBytes()
}
