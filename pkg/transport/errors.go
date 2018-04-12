package transport

type GoWinRMErr struct {
	Actual error
	Msg    string
}

func (e *GoWinRMErr) Error() string {
	if e.Msg == "" {
		return e.Actual.Error()
	}
	return e.Msg
}
