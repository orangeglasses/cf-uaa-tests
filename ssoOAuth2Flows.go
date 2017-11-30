package main

import (
	"net/http/cookiejar"
	"net/http"
	"bytes"
	"encoding/json"
	"strings"
	"net/url"
	"fmt"
	"golang.org/x/oauth2"
	"golang.org/x/net/html"
	"io"
	"errors"
)

const (
	clientCredentialsGrantType = "client_credentials"
	passwordGrantType          = "password"

	uaaResourceUrl = "http://smoketests-resource.cf-tst.intranet.rws.nl/uaaLogin"
	adfsResourceUrl = "http://smoketests-resource.cf-tst.intranet.rws.nl/adfsLogin"
)

// ClientCredentialsAuthentication performs the OAuth2 client credentials flow against UAA and returns the
// token and the result of the test.
func ClientCredentialsAuthentication(clientID, clientSecret, authDomain string) (TokenResponse, TestResult) {
	authResult := defaultTestResult()

	// Construct OAuth2 client_credentials grant request.
	// https://docs.cloudfoundry.org/api/uaa/version/4.7.0/index.html#client-credentials-grant
	clientCredentialsForm := url.Values{}
	clientCredentialsForm.Set("grant_type", clientCredentialsGrantType)
	clientCredentialsForm.Set("client_id", clientID)
	clientCredentialsForm.Set("client_secret", clientSecret)

	clientCredentialsGrantRequest, err := http.NewRequest(http.MethodPost, authDomain+"/oauth/token", strings.NewReader(clientCredentialsForm.Encode()))
	if err != nil {
		panic(err)
	}
	clientCredentialsGrantRequest.Header.Add("Accept", "application/json")
	clientCredentialsGrantRequest.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Execute request.
	httpClient := &http.Client{}
	clientCredentialsGrantResponse, err := httpClient.Do(clientCredentialsGrantRequest)
	if err != nil {
		panic(err)
	}
	defer clientCredentialsGrantResponse.Body.Close()

	// Parse token response.
	responseBuffer := new(bytes.Buffer)
	responseBuffer.ReadFrom(clientCredentialsGrantResponse.Body)
	var tokenResponse TokenResponse
	err = json.Unmarshal(responseBuffer.Bytes(), &tokenResponse)
	if err != nil {
		panic(err)
	}

	// Check response status code.
	statusCode := clientCredentialsGrantResponse.StatusCode
	if statusCode != http.StatusOK {
		authResult.Result = false
		authResult.StatusCode = &statusCode
		authResult.ParseErrorResponse(responseBuffer)
	}

	return tokenResponse, authResult
}

// PasswordAuthentication performs the OAuth2 password credentials flow against UAA and returns the
// JWT token and test result.
func PasswordAuthentication(clientID, clientSecret, authDomain, username, password string) (TokenResponse, TestResult) {
	authResult := defaultTestResult()

	// Construct OAuth2 password grant request.
	passwordGrantForm := url.Values{}
	passwordGrantForm.Set("grant_type", passwordGrantType)
	passwordGrantForm.Set("client_id", clientID)
	passwordGrantForm.Set("client_secret", clientSecret)
	passwordGrantForm.Set("response_type", "token")
	passwordGrantForm.Set("username", username)
	passwordGrantForm.Set("password", password)

	passwordGrantRequest, err := http.NewRequest(http.MethodPost, authDomain+"/oauth/token", strings.NewReader(passwordGrantForm.Encode()))
	if err != nil {
		panic(err)
	}
	passwordGrantRequest.Header.Add("Accept", "application/json")
	passwordGrantRequest.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Execute request.
	httpClient := &http.Client{}
	passwordGrantResponse, err := httpClient.Do(passwordGrantRequest)
	if err != nil {
		panic(err)
	}
	defer passwordGrantResponse.Body.Close()

	// Parse token response.
	responseBuffer := new(bytes.Buffer)
	responseBuffer.ReadFrom(passwordGrantResponse.Body)
	var tokenResponse TokenResponse
	err = json.Unmarshal(responseBuffer.Bytes(), &tokenResponse)
	if err != nil {
		panic(err)
	}

	// Check response status code.
	statusCode := passwordGrantResponse.StatusCode
	if statusCode != http.StatusOK {
		authResult.Result = false
		authResult.StatusCode = &statusCode

		// Try parse error response.
		authResult.ParseErrorResponse(responseBuffer)
	}

	return tokenResponse, authResult
}

func UaaAuthorizationCodeAuthentication(uaaSmokeUsername, uaaSmokePassword string) (TokenResponse, TestResult) {
	authResult := defaultTestResult()

	// Create http client with cookie jar (otherwise cookies are ignored).
	cookieJar, _ := cookiejar.New(nil)
	httpClient := http.Client{Jar: cookieJar}

	// Attempt to access resource that is protected by UAA client application.
	resp, err := httpClient.Get(uaaResourceUrl)
	if err != nil {
		authResult.Result = false
		authResult.Error = err.Error()
		return TokenResponse{}, authResult
	}
	defer resp.Body.Close()

	// Construct authorization base url from response.
	authBaseUrl := fmt.Sprintf("%s://%s", resp.Request.URL.Scheme, resp.Request.URL.Host)

	// Locate form element and input fields in response body to simulate login.
	form, fields, err := getFormDetails(resp.Body)
	if err != nil {
		authResult.Result = false
		authResult.Error = err.Error()
		return TokenResponse{}, authResult
	}

	// Enter username and password.
	for i, v := range fields {
		if v.name == "username" {
			fields[i].value = uaaSmokeUsername
		}
		if v.name == "password" {
			fields[i].value = uaaSmokePassword
		}
	}

	// Construct login request.
	authUrl := fmt.Sprintf("%s%s", authBaseUrl, form.action)
	loginForm := url.Values{}
	for _, f := range fields {
		loginForm.Set(f.name, f.value)
	}
	authRequest, err := http.NewRequest(strings.ToUpper(form.method), authUrl, strings.NewReader(loginForm.Encode()))
	if err != nil {
		panic(err)
	}
	authRequest.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Perform login.
	authResponse, err := httpClient.Do(authRequest)
	if err != nil {
		authResult.Result = false
		authResult.Error = err.Error()
		return TokenResponse{}, authResult
	}
	defer authResponse.Body.Close()

	// Parse response.
	statusCode := authResponse.StatusCode
	responseBuffer := new(bytes.Buffer)
	responseBuffer.ReadFrom(authResponse.Body)
	if statusCode == http.StatusBadRequest {
		// Parse error response.
		var authError authError
		_ = json.Unmarshal(responseBuffer.Bytes(), &authError)

		authResult.Result = false
		authResult.StatusCode = &statusCode
		authResult.Error = authError.Error
		authResult.ErrorDescription = authError.ErrorDescription
		return TokenResponse{}, authResult
	}

	// We received back the token.
	var token oauth2.Token
	_ = json.Unmarshal(responseBuffer.Bytes(), &token)

	return TokenResponse{AccessToken: token.AccessToken, TokenType: token.TokenType, RefreshToken: token.RefreshToken, ExpiresIn: int(token.Expiry.Unix())}, authResult
}

func AdfsAuthorizationCodeAuthentication(adfsSmokeUsername, adfsSmokePassword string) (TokenResponse, TestResult) {
	authResult := defaultTestResult()

	// Create http client with cookie jar (otherwise cookies are ignored).
	cookieJar, _ := cookiejar.New(nil)
	httpClient := http.Client{Jar: cookieJar}

	// Attempt to access resource that is protected by UAA client application.
	resp, err := httpClient.Get(adfsResourceUrl)
	if err != nil {
		authResult.Result = false
		authResult.Error = err.Error()
		return TokenResponse{}, authResult
	}
	defer resp.Body.Close()

	// Construct authorization base url from response (federatie.rws.nl).
	authBaseUrl := fmt.Sprintf("%s://%s", resp.Request.URL.Scheme, resp.Request.URL.Host)

	// We receive a redirect to an ADFS login form: parse the form to be able to POST it back.
	loginForm, loginFields, err := getFormDetails(resp.Body)
	for i, v := range loginFields {
		if v.name == "UserName" {
			loginFields[i].value = adfsSmokeUsername
		}
		if v.name == "Password" {
			loginFields[i].value = adfsSmokePassword
		}
	}
	authUrl := fmt.Sprintf("%s%s", authBaseUrl, loginForm.action)

	// Compose login form.
	loginFormValues := url.Values{}
	for _, f := range loginFields {
		loginFormValues.Set(f.name, f.value)
	}

	// Compose login request.
	loginRequest, err := http.NewRequest(strings.ToUpper(loginForm.method), authUrl, strings.NewReader(loginFormValues.Encode()))
	if err != nil {
		authResult.Result = false
		authResult.Error = err.Error()
		return TokenResponse{}, authResult
	}
	loginRequest.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Perform login request.
	loginResponse, err := httpClient.Do(loginRequest)
	if err != nil {
		authResult.Result = false
		authResult.Error = err.Error()
		return TokenResponse{}, authResult
	}
	defer loginResponse.Body.Close()

	// The result of the login is another form that allows us to go back to rws.login.cf-prod.intranet.rws.nl.
	samlForm, samlFields, err := getFormDetails(loginResponse.Body)

	// Compose SAML form.
	samlFormValues := url.Values{}
	for _, f := range samlFields {
		samlFormValues.Set(f.name, f.value)
	}

	// Compose SAML request.
	samlAuthRequest, err := http.NewRequest(strings.ToUpper(samlForm.method), samlForm.action, strings.NewReader(samlFormValues.Encode()))
	if err != nil {
		authResult.Result = false
		authResult.Error = err.Error()
		return TokenResponse{}, authResult
	}
	samlAuthRequest.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Perform SAML request.
	samlAuthResponse, err := httpClient.Do(samlAuthRequest)
	if err != nil {
		authResult.Result = false
		authResult.Error = err.Error()
		return TokenResponse{}, authResult
	}
	defer samlAuthResponse.Body.Close()

	// Parse response.
	statusCode := samlAuthResponse.StatusCode
	responseBuffer := new(bytes.Buffer)
	responseBuffer.ReadFrom(samlAuthResponse.Body)
	if statusCode == http.StatusBadRequest {
		// Parse error response.
		var authError authError
		_ = json.Unmarshal(responseBuffer.Bytes(), &authError)

		authResult.Result = false
		authResult.StatusCode = &statusCode
		authResult.Error = authError.Error
		authResult.ErrorDescription = authError.ErrorDescription
		return TokenResponse{}, authResult
	}

	// We received back the token.
	var token oauth2.Token
	_ = json.Unmarshal(responseBuffer.Bytes(), &token)

	return TokenResponse{AccessToken: token.AccessToken, TokenType: token.TokenType, RefreshToken: token.RefreshToken, ExpiresIn: int(token.Expiry.Unix())}, authResult
}

func getFormDetails(doc io.Reader) (formInfo, []fieldInfo, error) {
	// Parse html document that contains our login form.
	root, err := html.Parse(doc)
	if err != nil {
		return formInfo{}, nil, err
	}

	// Find form html node.
	formNode := findForm(root)
	if formNode == nil {
		return formInfo{}, nil, errors.New("No form found in UAA login form")
	}

	// Get relevant attributes from form.
	var form formInfo
	for _, att := range formNode.Attr {
		if att.Key == "action" {
			form.action = att.Val
		}
		if att.Key == "method" {
			form.method = att.Val
		}
	}

	// Get fields inside form.
	fields := findInputs(formNode)

	// Filter out submit button.
	for i, v := range fields {
		if v.fieldType == "submit" {
			fields = append(fields[:i], fields[i+1:]...)
		}
	}

	return form, fields, nil
}

func findForm(root *html.Node) *html.Node {
	var formFinder func(*html.Node) *html.Node
	formFinder = func(n *html.Node) (form *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			form = n
			return
		}
		for c := n.FirstChild; c != nil && form == nil; c = c.NextSibling {
			form = formFinder(c)
		}
		return
	}
	return formFinder(root)
}

func findInputs(formNode *html.Node) []fieldInfo {
	var fields []fieldInfo

	var inputFinder func(*html.Node)
	inputFinder = func(n *html.Node) {
		// Find input attributes inside form: name and value.
		if n.Type == html.ElementNode && n.Data == "input" {
			var field fieldInfo
			for _, att := range n.Attr {
				if att.Key == "name" {
					field.name = att.Val
				}
				if att.Key == "value" {
					field.value = att.Val
				}
				if att.Key == "type" {
					field.fieldType = att.Val
				}
			}
			fields = append(fields, field)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			inputFinder(c)
		}
	}
	inputFinder(formNode)
	return fields
}

type formInfo struct {
	method string
	action string
}

type fieldInfo struct {
	fieldType string
	name      string
	value     string
}

type authError struct {
	Error            string `json:error,omitempty`
	ErrorDescription string `json:error_description,omitempty`
}

