package envelope

import (
	"fmt"

	. "github.com/beevik/etree"
)

type ShellEnvelopeBodyWriter struct {
	envelope *EnvelopeWriter
	π        *Element
}

func (bs *ShellEnvelopeBodyWriter) InputStreams(inputStreams string) *ShellEnvelopeBodyWriter {
	inputStreamsEle := bs.π.SelectElement("InputStreams")
	if inputStreamsEle == nil {
		inputStreamsEle = bs.envelope.createChildElementFor(bs.π, "InputStreams", ns_rsp)
	}
	inputStreamsEle.SetText(inputStreams)

	return bs
}

func (bs *ShellEnvelopeBodyWriter) OutputStreams(outputStreams string) *ShellEnvelopeBodyWriter {
	outputStreamsEle := bs.π.SelectElement("outputStreams")
	if outputStreamsEle == nil {
		outputStreamsEle = bs.envelope.createChildElementFor(bs.π, "outputStreams", ns_rsp)
	}
	outputStreamsEle.SetText(outputStreams)

	return bs
}

func (bs *ShellEnvelopeBodyWriter) WorkingDirectory(workingDirectory string) *ShellEnvelopeBodyWriter {
	workingDirectoryEle := bs.π.SelectElement("workingDirectory")
	if workingDirectoryEle == nil {
		workingDirectoryEle = bs.envelope.createChildElementFor(bs.π, "workingDirectory", ns_rsp)
	}
	workingDirectoryEle.SetText(workingDirectory)

	return bs
}

func (bs *ShellEnvelopeBodyWriter) LifeTime(lifetime uint64) *ShellEnvelopeBodyWriter {
	lifetimeEle := bs.π.SelectElement("Lifetime")
	if lifetimeEle == nil {
		lifetimeEle = bs.envelope.createChildElementFor(bs.π, "Lifetime", ns_rsp)
	}
	lifetimeEle.SetText(fmt.Sprint(lifetime))

	return bs
}

func (bs *ShellEnvelopeBodyWriter) IdleTimeOut(idleTimeout uint64) *ShellEnvelopeBodyWriter {
	idleTimeOutEle := bs.π.SelectElement("IdleTimeOut")
	if idleTimeOutEle == nil {
		idleTimeOutEle = bs.envelope.createChildElementFor(bs.π, "IdleTimeOut", ns_rsp)
	}
	idleTimeOutEle.SetText(fmt.Sprintf("PT%dS", idleTimeout))

	return bs
}

func (bs *ShellEnvelopeBodyWriter) EnvironmentVariables(envVars map[string]string) *ShellEnvelopeBodyWriter {
	environmentVariablesEle := bs.π.SelectElement("Environment")
	if environmentVariablesEle != nil {
		bs.π.RemoveChild(environmentVariablesEle)
	}

	environmentVariablesEle = bs.envelope.createChildElementFor(bs.π, "Environment", ns_rsp)

	for k, v := range envVars {
		envVarEle := environmentVariablesEle.CreateElement("rsp:Variable")
		envVarEle.CreateAttr("Name", k)
		envVarEle.SetText(v)
	}

	return bs
}

func (bs *ShellEnvelopeBodyWriter) ToString() (string, error) {
	return bs.envelope.ToString()
}

func (bs *ShellEnvelopeBodyWriter) ToBytes() ([]byte, error) {
	return bs.envelope.ToBytes()
}
