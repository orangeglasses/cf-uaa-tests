package main

import (
	"bytes"
	"encoding/json"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	JwtID        string `json:"jti"`
}

func (result *TestResult) ParseErrorResponse(responseBuffer *bytes.Buffer) {
	var errorResponse map[string]interface{}
	if err := json.Unmarshal(responseBuffer.Bytes(), &errorResponse); err == nil {
		if tokenGrantError, exists := errorResponse["error"]; exists {
			result.Error = tokenGrantError.(string)
		}
		if tokenGrantErrorDescription, exists := errorResponse["error_description"]; exists {
			result.ErrorDescription = tokenGrantErrorDescription.(string)
		}
	}
}

type TestResult struct {
	Result           bool   `json:"result"`
	StatusCode       *int   `json:"statusCode,omitempty"`
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"errorDescription,omitempty"`
}

func defaultTestResult() TestResult {
	return TestResult{Result: true}
}

func (r TestResult) HasError() bool {
	return !r.Result
}

