package main

import (
	"fmt"

	"github.com/cloudfoundry-community/go-cfenv"
)

const (
	uaaSmokeUsername = "smokeuser"
	uaaSmokePassword = "smokepassword"
	smokeScope       = "smoketest.extinguish"
)

type SmokeTest interface {
	run() interface{}
}

type ssoTest struct {
	authDomain   string
	clientId     string
	clientSecret string
}

func main() {}

func ssoTestNew(env *cfenv.App) SmokeTest {
	identityServices, err := env.Services.WithLabel("p-identity")
	if err != nil {
		return &ssoTest{"", "", ""}
	}

	creds := identityServices[0].Credentials
	return &ssoTest{
		creds["auth_domain"].(string),
		creds["client_id"].(string),
		creds["client_secret"].(string),
	}
}

func (t *ssoTest) run() interface{} {
	fmt.Println("Found client id: " + t.clientId)
	if t.clientId == "" {
		fmt.Println("No client_id found")
		return false
	}

	oauth2FlowsTestResult := &Oauth2FlowsTestResult{}

	// Authenticate against UAA using client_credentials grant type and provided client id and secret.
	clientCredentialsTokenResponse, clientCredentialsTestResult := ClientCredentialsAuthentication(t.clientId, t.clientSecret, t.authDomain)
	oauth2FlowsTestResult.ClientCredentials = &clientCredentialsTestResult
	if clientCredentialsTestResult.HasError() {
		return oauth2FlowsTestResult
	}

	// Create a local user, authenticating with the token we acquired above (which should have scim.write scope).
	// SCIM stands for System for Cross-domain Identity Management (http://www.simplecloud.info/).
	user := ScimUser{
		UserName:     uaaSmokeUsername,
		Name:         ScimUserName{Formatted: "Smoke User", FamilyName: "User", GivenName: "Smoke"},
		Emails:       []ScimAttribute{{Value: "smokeuser@smoke.nl"}},
		Active:       true,
		Verified:     true,
		Origin:       "uaa",
		Password:     uaaSmokePassword,
		ScimResource: ScimResource{ExternalID: "", Meta: nil, Schemas: []string{"urn:scim:schemas:core:1.0"}},
	}
	createdUser, createUserTestResult := CreateUser(user, clientCredentialsTokenResponse.AccessToken, t.authDomain)
	oauth2FlowsTestResult.CreateUser = &createUserTestResult
	if createUserTestResult.HasError() {
		return oauth2FlowsTestResult
	}

	if createdUser != nil {
		// Delete local user after we're finished (via defer).
		defer func(res *Oauth2FlowsTestResult) {
			deleteUserTestResult := DeleteUser(createdUser.ID, clientCredentialsTokenResponse.AccessToken, t.authDomain)
			res.DeleteUser = &deleteUserTestResult
		}(oauth2FlowsTestResult)

		// Get all groups (to be able to assign new user to groups).
		groups, getGroupsResult := GetGroups(clientCredentialsTokenResponse.AccessToken, t.authDomain)
		oauth2FlowsTestResult.GetGroups = &getGroupsResult
		if getGroupsResult.HasError() {
			return oauth2FlowsTestResult
		}

		// Get smoketest.extinguish group.
		var smokeExtinguishGroup ScimResource
		for i := range groups {
			if groups[i].DisplayName == smokeScope {
				smokeExtinguishGroup = groups[i]
				break
			}
		}

		// Assign user to smoketest.extinguish group.
		addMemberResult := AddGroupMember(smokeExtinguishGroup.ID, createdUser.ID, clientCredentialsTokenResponse.AccessToken, t.authDomain)
		oauth2FlowsTestResult.AddGroupMember = &addMemberResult
		if addMemberResult.HasError() {
			return oauth2FlowsTestResult
		}

		// Authenticate directly against UAA with newly created user using password grant type.
		// (https://tools.ietf.org/html/rfc6749#section-4.3)
		// This does not involve ADFS yet, goes directly to UAA.
		_, userTokenTestResult := PasswordAuthentication(t.clientId, t.clientSecret, t.authDomain, uaaSmokeUsername, uaaSmokePassword)
		oauth2FlowsTestResult.Password = &userTokenTestResult
		if userTokenTestResult.HasError() {
			return oauth2FlowsTestResult
		}

		// Authenticate against UAA using the authorization code grant type (https://tools.ietf.org/html/rfc6749#section-4.1).
		// Does still not involve ADFS yet. This requires an application that is protected by a UAA client.
		_, uaaAuthorizationCodeResult := UaaAuthorizationCodeAuthentication(uaaSmokeUsername, uaaSmokePassword)
		oauth2FlowsTestResult.AuthorizationCodeUAA = &uaaAuthorizationCodeResult
		if uaaAuthorizationCodeResult.HasError() {
			return oauth2FlowsTestResult
		}

		// Authenticate against ADFS using the authorization code grant type (https://tools.ietf.org/html/rfc6749#section-4.1).
		_, adfsAuthorizationCodeResult := AdfsAuthorizationCodeAuthentication("ad\\aduser", "password")
		oauth2FlowsTestResult.AuthorizationCodeAdfs = &adfsAuthorizationCodeResult
		if adfsAuthorizationCodeResult.HasError() {
			return oauth2FlowsTestResult
		}
	}

	return oauth2FlowsTestResult
}

type Oauth2FlowsTestResult struct {
	ClientCredentials     *TestResult `json:"clientCredentials,omitempty"`
	CreateUser            *TestResult `json:"createUser,omitempty"`
	GetGroups             *TestResult `json:"getGroups,omitempty"`
	AddGroupMember        *TestResult `json:"addGroupMemberResult,omitempty"`
	Password              *TestResult `json:"password,omitempty"`
	AuthorizationCodeUAA  *TestResult `json:"authCodeUAA,omitempty"`
	AuthorizationCodeAdfs *TestResult `json:"authCodeAdfs,omitempty"`
	DeleteUser            *TestResult `json:"deleteUser,omitempty"`
}
