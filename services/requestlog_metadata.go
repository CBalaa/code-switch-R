package services

import (
	"bytes"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

const requestedModelContextKey = "request_log_requested_model"

// populateRequestLogIdentity keeps the client model and relay-key metadata
// attached when a helper creates a log after model mapping has already taken
// place. The context value is optional; callers that do not set it retain the
// model passed to startActiveRequestLog.
func populateRequestLogIdentity(c *gin.Context, entry *ReqeustLog) {
	if c == nil || entry == nil {
		return
	}
	if requested := strings.TrimSpace(c.GetString(requestedModelContextKey)); requested != "" {
		entry.RequestedModel = requested
	}
	if name := relayKeyNameFromContext(c); name != "" {
		entry.RelayKeyName = name
	}
}

// responseModelObserver is useful for response paths that forward arbitrary
// chunks instead of complete SSE lines (for example image payload streams).
// It keeps model inspection bounded so a large base64 line is forwarded by the
// caller without being copied indefinitely just for metadata extraction.
type responseModelObserver struct {
	entry    *ReqeustLog
	line     []byte
	skipping bool
}

func newResponseModelObserver(entry *ReqeustLog) *responseModelObserver {
	return &responseModelObserver{entry: entry}
}

func (o *responseModelObserver) Write(data []byte) {
	if o == nil {
		return
	}
	const maxLine = 8 << 20
	for len(data) > 0 {
		end := bytes.IndexByte(data, '\n')
		part := data
		if end >= 0 {
			part = data[:end]
		}
		if !o.skipping {
			if len(o.line)+len(part) > maxLine {
				o.line = nil
				o.skipping = true
			} else {
				o.line = append(o.line, part...)
			}
		}
		if end < 0 {
			return
		}
		o.Finish()
		data = data[end+1:]
	}
}

func (o *responseModelObserver) Finish() {
	if o == nil {
		return
	}
	if !o.skipping {
		parseEventPayload(string(o.line), captureResponseModel, o.entry)
	}
	o.line = o.line[:0]
	o.skipping = false
}

// captureResponseModel only inspects protocol metadata fields. It deliberately
// ignores content and tool arguments, which may contain arbitrary model names.
// An absent model remains unknown instead of falling back to the requested one.
func captureResponseModel(data string, entry *ReqeustLog) {
	if entry == nil {
		return
	}
	for _, path := range []string{"response.model", "message.model", "model", "modelVersion"} {
		value := gjson.Get(data, path)
		if value.Type != gjson.String {
			continue
		}
		model := strings.TrimSpace(value.String())
		if model == "" {
			continue
		}
		if entry.ResponseModel != model {
			entry.ResponseModel = model
			entry.syncActiveRequest()
		}
		return
	}
}
