package aghhttp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/log"
)

// JSON Utilities

// nsecPerMsec is the number of nanoseconds in a millisecond.
const nsecPerMsec = float64(time.Millisecond / time.Nanosecond)

// JSONDuration is a time.Duration that can be decoded from JSON and encoded
// into JSON according to our API conventions.
type JSONDuration time.Duration

// type check
var _ json.Marshaler = JSONDuration(0)

// MarshalJSON implements the json.Marshaler interface for JSONDuration.  err is
// always nil.
func (d JSONDuration) MarshalJSON() (b []byte, err error) {
	msec := float64(time.Duration(d)) / nsecPerMsec
	b = strconv.AppendFloat(nil, msec, 'f', -1, 64)

	return b, nil
}

// type check
var _ json.Unmarshaler = (*JSONDuration)(nil)

// UnmarshalJSON implements the json.Marshaler interface for *JSONDuration.
func (d *JSONDuration) UnmarshalJSON(b []byte) (err error) {
	if d == nil {
		return fmt.Errorf("json duration is nil")
	}

	msec, err := strconv.ParseFloat(string(b), 64)
	if err != nil {
		return fmt.Errorf("parsing json time: %w", err)
	}

	*d = JSONDuration(int64(msec * nsecPerMsec))

	return nil
}

// JSONTime is a time.Time that can be decoded from JSON and encoded into JSON
// according to our API conventions.
type JSONTime time.Time

// type check
var _ json.Marshaler = JSONTime{}

// MarshalJSON implements the json.Marshaler interface for JSONTime.  err is
// always nil.
func (t JSONTime) MarshalJSON() (b []byte, err error) {
	msec := float64(time.Time(t).UnixNano()) / nsecPerMsec
	b = strconv.AppendFloat(nil, msec, 'f', -1, 64)

	return b, nil
}

// type check
var _ json.Unmarshaler = (*JSONTime)(nil)

// UnmarshalJSON implements the json.Marshaler interface for *JSONTime.
func (t *JSONTime) UnmarshalJSON(b []byte) (err error) {
	if t == nil {
		return fmt.Errorf("json time is nil")
	}

	msec, err := strconv.ParseFloat(string(b), 64)
	if err != nil {
		return fmt.Errorf("parsing json time: %w", err)
	}

	*t = JSONTime(time.Unix(0, int64(msec*nsecPerMsec)).UTC())

	return nil
}

// WriteJSONResponse sets the content-type header in w.Header() to
// "application/json", writes a header with a "200 OK" status, encodes resp to
// w, calls [Error] on any returned error, and returns it as well.
func WriteJSONResponse(w http.ResponseWriter, r *http.Request, resp any) (err error) {
	return WriteJSONResponseCode(w, r, http.StatusOK, resp)
}

// WriteJSONResponseCode is like [WriteJSONResponse] but adds the ability to
// redefine the status code.
func WriteJSONResponseCode(w http.ResponseWriter, r *http.Request, code int, resp any) (err error) {
	h := w.Header()
	h.Set(httphdr.ContentType, HdrValApplicationJSON)
	h.Set(httphdr.Server, UserAgent())

	w.WriteHeader(code)

	err = json.NewEncoder(w).Encode(resp)
	if err != nil {
		Error(r, w, http.StatusInternalServerError, "encoding resp: %s", err)
	}

	return err
}

// WriteJSONOKResponse writes headers with the code 200 OK, encodes v into w,
// and logs any errors it encounters.  r is used to get additional information
// from the request.
func WriteJSONOKResponse(w http.ResponseWriter, r *http.Request, v any) {
	_ = WriteJSONResponseCode(w, r, http.StatusOK, v)
}

// ErrorCode is the error code as used by the HTTP API.  See the ErrorCode
// definition in the OpenAPI specification.
type ErrorCode string

// ErrorCode constants.
//
// TODO(a.garipov): Expand and document codes.
const (
	// ErrorCodeTMP000 is the temporary error code used for all errors.
	ErrorCodeTMP000 = ""
)

// HTTPAPIErrorResp is the error response as used by the HTTP API.  See the
// BadRequestResp, InternalServerErrorResp, and similar objects in the OpenAPI
// specification.
type HTTPAPIErrorResp struct {
	Code ErrorCode `json:"code"`
	Msg  string    `json:"msg"`
}

// WriteJSONErrorResponse encodes err as a JSON error into w, and logs any
// errors it encounters.  r is used to get additional information from the
// request.
func WriteJSONErrorResponse(w http.ResponseWriter, r *http.Request, err error) {
	log.Error("websvc: %s %s: %s", r.Method, r.URL.Path, err)

	_ = WriteJSONResponseCode(w, r, http.StatusUnprocessableEntity, &HTTPAPIErrorResp{
		Code: ErrorCodeTMP000,
		Msg:  err.Error(),
	})
}
