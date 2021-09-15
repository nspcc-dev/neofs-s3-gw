package api

type (
	// ObjectRequest represents object request data.
	ObjectRequest struct {
		Bucket string
		Object string
		Method string
	}
)

// Key used for Get/SetReqInfo.
type contextKeyType string

const ctxRequestInfo = contextKeyType("NeoFS-S3-GW")
