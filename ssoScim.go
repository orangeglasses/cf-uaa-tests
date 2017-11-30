package main

import "time"

type ScimResource struct {
	ID          string    `json:"id"`
	ExternalID  string    `json:"externalId"`
	Meta        *ScimMeta `json:"meta,omitempty"`
	DisplayName string    `json:"displayName"`
	Schemas     []string  `json:"schemas"`
}

// http://www.simplecloud.info/specs/draft-scim-core-schema-01.html
type ScimUser struct {
	ScimResource
	UserName string          `json:"userName"`
	Name     ScimUserName    `json:"name"`
	Active   bool            `json:"active"`
	Password string          `json:"password"`
	Verified bool            `json:"verified"`
	Emails   []ScimAttribute `json:"emails"`
	Origin   string          `json:"origin"`
	Groups   []ScimAttribute `json:"groups,omitempty"`
}

type ScimGroup struct {
	ScimResource
	Description string          `json:"description"`
	Members     []ScimAttribute `json:"members"`
}

type ScimList struct {
	TotalResults int            `json:"totalResults"`
	ItemsPerPage int            `json:"itemsPerPage"`
	StartIndex   int            `json:"startIndex"`
	Resources    []ScimResource `json:"Resources"`
}

// http://www.simplecloud.info/specs/draft-scim-core-schema-01.html
type ScimMeta struct {
	Created      time.Time `json:"created,omitempty"`
	LastModified time.Time `json:"lastModified,omitempty"`
	Location     string    `json:"location,omitempty"`
	Version      int       `json:"version"`
}

// http://www.simplecloud.info/specs/draft-scim-core-schema-01.html
type ScimUserName struct {
	Formatted       string `json:"formatted"`
	FamilyName      string `json:"familyName"`
	GivenName       string `json:"givenName"`
	MiddleName      string `json:"middleName"`
	HonorificPrefix string `json:"honorificPrefix"`
	HonorificSuffix string `json:"honorificSuffix"`
}

// http://www.simplecloud.info/specs/draft-scim-core-schema-01.html
type ScimAttribute struct {
	Value     string `json:"value"`
	Display   string `json:"display"`
	Type      string `json:"type"`
	Primary   bool   `json:"primary"`
	Operation string `json:"operation"`
}

