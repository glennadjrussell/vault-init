package main

import (
	"bytes"
	"encoding/json"
	"net/http"
)

vars (
	github_auth_endpoint = "/sys/auth/github"
)

type GithubAuthRequest struct {
	Token string `json:"token"`
	Org string `json:"organization"`
	Team string `json:"team"`
	Host string `json:"base_url"`
}

type GithubMapTeamRequest struct {
	Team string `json:"team_name"`
	Policies []string `json:"value"`
}

type PolicyCreateRequest struct {
	Policy string `json:"policy"`
}

func mapGithubTeam(key string) (bool, error) {
}

//
// {"type":"github","description":"","config":{"options":null,"default_lease_ttl":"0s","max_lease_ttl":"0s","force_no_cache":false},"local":false,"seal_wrap":false,"external_entropy_access":false,"options":null}
//
func enableGithubAuth(token string) (bool, error) {
	authRequest := GithubAuthRequest{
	}

	authRequestData, err := json.Marshal(&authRequest)
	if err != nil {
		return false, err
	}

	r := bytes.NewReader(authRequestData)
	request, err := http.NewRequest(http.MethodPut, vaultAddr+"/auth/github/config", r)
	if err != nil {
		return false, err
	}

	response, err := httpClient.Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200  {
		return false, fmt.Errorf("%d", response.StatusCode)
	}

	// Possibly not needed if a 200
	authRequestResponseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return false, err
	}
}

func createPolicy(token string, key string, policy string) (bool, error) {
	policyRequest := PolicyRequest{
		Policy: policy
	}

	policyRequestData, err := json.Marshal(&policyRequest)
	if err != nil {
		return false, err
	}

	r := bytes.NewReader(policyRequestData)
	request, err := http.NewRequest(http.MethodPut,  vaultAddr+"/v1/sys/policy/"+key, r)

	response, err := httpClient.do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		return false, fmt.Errorf("policy creation: non-200 status code: %d", response.StatusCode)
	}

	return true, nil
}

func initializeAuth(token string) (bool, err) {
	res, err := createPolicy(token, "vault_admins", "/policies/admin.hcl")
	if err != nil {
		return false, err
	}

	res, err := enableGithubAuth(token)
	if err != nil {
		return false, err
	}

	return false, nil
}

