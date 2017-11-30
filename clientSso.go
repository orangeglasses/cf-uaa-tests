package main

import (
	"fmt"
	"net/http"
	"golang.org/x/oauth2"
	"encoding/json"

	"github.com/cloudfoundry-community/go-cfenv"
)

const (
	htmlIndex = `<html>
	<body>
	<a href="/uaaLogin">Log in with UAA</a><br />
	<a href="/adfsLogin">Log in with ADFS</a>
	</body>
	</html>`
)

var (
	oauth2UaaConfig = &oauth2.Config{
		Scopes: []string{"smoketest.extinguish"},
	}
	oauth2AdfsConfig = &oauth2.Config{
		Scopes: []string{"openid"},
	}
	// Some random string, should be random for each request but we use it to distinguish between response from
	// UAA and ADFS.
	oauth2UaaStateString  = "random_uaa"
	oauth2AdfsStateString = "random_adfs"
)

func main() {
	appEnv, err := cfenv.Current()
	if err != nil {
		panic(err)
	}

	appUri := appEnv.ApplicationURIs[0]

	// Configure SSO via UAA.
	ssoUaaService, err := appEnv.Services.WithName("smoketests-sso-uaa")
	if err != nil {
		panic(err)
	}

	uaaCreds := ssoUaaService.Credentials
	oauth2UaaConfig.ClientID = uaaCreds["client_id"].(string)
	oauth2UaaConfig.ClientSecret = uaaCreds["client_secret"].(string)
	uaaAuthDomain := uaaCreds["auth_domain"].(string)
	oauth2UaaConfig.Endpoint.AuthURL = fmt.Sprintf("%s/%s", uaaAuthDomain, "oauth/authorize")
	oauth2UaaConfig.Endpoint.TokenURL = fmt.Sprintf("%s/%s", uaaAuthDomain, "oauth/token")
	oauth2UaaConfig.RedirectURL = fmt.Sprintf("http://%s/uaaCallback", appUri)

	// Configure SSO via ADFS.
	ssoAdfsService, err := appEnv.Services.WithName("smoketests-sso-adfs")
	if err != nil {
		panic(err)
	}

	adfsCreds := ssoAdfsService.Credentials
	oauth2AdfsConfig.ClientID = adfsCreds["client_id"].(string)
	oauth2AdfsConfig.ClientSecret = adfsCreds["client_secret"].(string)
	adfsAuthDomain := adfsCreds["auth_domain"].(string)
	oauth2AdfsConfig.Endpoint.AuthURL = fmt.Sprintf("%s/%s", adfsAuthDomain, "oauth/authorize")
	oauth2AdfsConfig.Endpoint.TokenURL = fmt.Sprintf("%s/%s", adfsAuthDomain, "oauth/token")
	oauth2AdfsConfig.RedirectURL = fmt.Sprintf("http://%s/adfsCallback", appUri)

	http.HandleFunc("/", handleMain)
	http.HandleFunc("/uaaLogin", handleUaaLogin)
	http.HandleFunc("/uaaCallback", handleCallback(oauth2UaaConfig, oauth2UaaStateString))
	http.HandleFunc("/adfsLogin", handleAdfsLogin)
	http.HandleFunc("/adfsCallback", handleCallback(oauth2AdfsConfig, oauth2AdfsStateString))
	http.ListenAndServe(fmt.Sprintf(":%v", appEnv.Port), nil)
}

func handleMain(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, htmlIndex)
}

func handleUaaLogin(w http.ResponseWriter, r *http.Request) {
	url := oauth2UaaConfig.AuthCodeURL(oauth2UaaStateString)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleAdfsLogin(w http.ResponseWriter, r *http.Request) {
	url := oauth2AdfsConfig.AuthCodeURL(oauth2AdfsStateString)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleCallback(oauth2Config *oauth2.Config, stateString string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		queryParams := r.URL.Query()

		// Check that state parameter is available.
		state, found := queryParams["state"]
		if !found {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "application/json")
			js, _ := json.Marshal(authenticationError{"No oauth2 state", fmt.Sprintf("Expected oauth2 state '%s' but no state was found", stateString)})
			w.Write(js)
			return
		}

		// Check state against known state.
		if state[0] != stateString {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "application/json")
			js, _ := json.Marshal(authenticationError{"Invalid oauth2 state", fmt.Sprintf("Invalid oauth2 state: expected '%s', got '%s'", stateString, state[0])})
			w.Write(js)
			return
		}

		// Get authorization code.
		code, found := queryParams["code"]
		if !found {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "application/json")
			var authError authenticationError

			// Check if we have error and error_description params in query.
			error, foundError := queryParams["error"]
			errorDescription, foundErrorDescription := queryParams["error_description"]
			if foundError {
				authError = authenticationError{Error: error[0]}
				if foundErrorDescription {
					authError.ErrorDescription = errorDescription[0]
				}
			} else {
				authError = authenticationError{"No code parameter", "Expected code parameter in request for token exchange"}
			}

			js, _ := json.Marshal(authError)
			w.Write(js)
			return
		}

		// Exchange authorization code for token.
		token, err := oauth2Config.Exchange(oauth2.NoContext, code[0])
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "application/json")
			js, _ := json.Marshal(authenticationError{Error: err.Error()})
			w.Write(js)
			return
		}

		// We received a token, whoopdeedoo.
		w.Header().Set("Content-Type", "application/json")
		js, _ := json.Marshal(token)
		w.Write(js)
	}
}

type authenticationError struct {
	Error            string `json:error,omitempty`
	ErrorDescription string `json:error_description,omitempty`
}
