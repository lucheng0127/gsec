package errorx

const (
	defaultCode = 1001

	// Auth code
	AuthDefaultCode          = 1011
	AuthUserNotExistCode     = 1012
	AuthPasswordNotMatchCode = 1013
	AuthJWTGenerateErrCode   = 1014
	AuthForbideCode          = 1015
)

type CodeError struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
}

type CodeErrorResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
}

func NewCodeError(code int, msg string) error {
	return &CodeError{Code: code, Msg: msg}
}

func NewDefaultError(msg string) error {
	return NewCodeError(defaultCode, msg)
}

func (e *CodeError) Error() string {
	return e.Msg
}

func (e *CodeError) Data() *CodeErrorResponse {
	return &CodeErrorResponse{
		Code: e.Code,
		Msg:  e.Msg,
	}
}
