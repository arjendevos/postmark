package postmark

import (
	"fmt"
	"net/url"
)

// Domain contains the details of the signature of the senders
type Domain struct {
	Name                          string
	SPFVerified                   bool
	SPFHost                       string
	SPFTextValue                  string
	DKIMVerified                  bool
	WeakDKIM                      bool
	DKIMHost                      string
	DKIMTextValue                 string
	DKIMPendingHost               string
	DKIMPendingTextValue          string
	DKIMRevokedHost               string
	DKIMRevokedTextValue          string
	SafeToRemoveRevokedKeyFromDNS bool
	DKIMUpdateStatus              string
	ReturnPathDomain              string
	ReturnPathDomainVerified      bool
	ReturnPathDomainCNAMEValue    string
	ID                            int
}

type DomainInfo struct {
	Name                     string
	SPFVerified              bool
	DKIMVerified             bool
	WeakDKIM                 bool
	ReturnPathDomainVerified bool
	ID                       int
}

type CreateDomain struct {
	Name             string
	ReturnPathDomain string
}

type EditDomain struct {
	ReturnPathDomain string
}

type RotatedDKIM struct {
	Name                          string
	DKIMVerified                  bool
	WeakDKIM                      bool
	DKIMHost                      string
	DKIMTextValue                 string
	DKIMPendingHost               string
	DKIMPendingTextValue          string
	DKIMRevokedHost               string
	DKIMRevokedTextValue          string
	SafeToRemoveRevokedKeyFromDNS bool
	DKIMUpdateStatus              string
	ID                            int
}

///////////////////////////////////////
///////////////////////////////////////

// DomainList is just a list of Domain as they are in the response
type DomainList struct {
	TotalCount int
	Domains    []DomainInfo
}

// GetDomains gets a list of domains, limited by count and paged by offset
func (client *Client) GetDomains(count, offset int64) (DomainList, error) {
	res := DomainList{}

	values := &url.Values{}
	values.Add("count", fmt.Sprintf("%d", count))
	values.Add("offset", fmt.Sprintf("%d", offset))

	err := client.doRequest(parameters{
		Method:    "GET",
		Path:      fmt.Sprintf("domains?%s", values.Encode()),
		TokenType: server_token,
	}, &res)
	return res, err
}

///////////////////////////////////////
///////////////////////////////////////

// GetDomain fetches a specific domain via domainID
func (client *Client) GetDomain(domainID string) (Domain, error) {
	res := Domain{}

	err := client.doRequest(parameters{
		Method:    "GET",
		Path:      fmt.Sprintf("domains/%s", domainID),
		TokenType: server_token,
	}, &res)
	return res, err
}

///////////////////////////////////////
///////////////////////////////////////

// CreateDomain saves a new domain
func (client *Client) CreateDomain(domain CreateDomain) (Domain, error) {
	res := Domain{}
	err := client.doRequest(parameters{
		Method:    "POST",
		Path:      "domains",
		Payload:   domain,
		TokenType: server_token,
	}, &res)
	return res, err
}

///////////////////////////////////////
///////////////////////////////////////

// EditDomain updates details for a specific domain with domainID
func (client *Client) EditDomain(domainID string, template EditDomain) (Domain, error) {
	res := Domain{}
	err := client.doRequest(parameters{
		Method:    "PUT",
		Path:      fmt.Sprintf("domains/%s", domainID),
		Payload:   template,
		TokenType: server_token,
	}, &res)
	return res, err
}

///////////////////////////////////////
///////////////////////////////////////

// DeleteDomain removes a domain (with domainID)
func (client *Client) DeleteDomain(domainID string) error {
	res := APIError{}
	err := client.doRequest(parameters{
		Method:    "DELETE",
		Path:      fmt.Sprintf("domains/%s", domainID),
		TokenType: server_token,
	}, &res)

	if res.ErrorCode != 0 {
		return res
	}

	return err
}

///////////////////////////////////////
///////////////////////////////////////

// VerifyDKIM verifies the DKIM record for a domain (with domainID)
func (client *Client) VerifyDKIM(domainID string) (Domain, error) {
	res := Domain{}
	err := client.doRequest(parameters{
		Method:    "PUT",
		Path:      fmt.Sprintf("domains/%s/verifyDkim", domainID),
		TokenType: server_token,
	}, &res)

	return res, err
}

///////////////////////////////////////
///////////////////////////////////////

// VerifyReturnPath verifies the return path for a domain (with domainID)
func (client *Client) VerifyReturnPath(domainID string) (Domain, error) {
	res := Domain{}
	err := client.doRequest(parameters{
		Method:    "PUT",
		Path:      fmt.Sprintf("domains/%s/verifyReturnPath", domainID),
		TokenType: server_token,
	}, &res)

	return res, err
}

///////////////////////////////////////
///////////////////////////////////////

// RotateDKIM rotates the DKIM record for a domain (with domainID)
func (client *Client) RotateDKIM(domainID string) (RotatedDKIM, error) {
	res := RotatedDKIM{}
	err := client.doRequest(parameters{
		Method:    "POST",
		Path:      fmt.Sprintf("domains/%s/rotatedkim", domainID),
		TokenType: server_token,
	}, &res)

	return res, err
}

///////////////////////////////////////
///////////////////////////////////////
