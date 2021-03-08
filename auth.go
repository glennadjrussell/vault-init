package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	//"io/ioutil"
	"net/http"
	"log"
)

var (
	//httpClient  *http.Client
)

type GithubAuthConfig struct {
	Options []string `json:"options"`
	DefaultLeaseTtl string `json:"default_lease_ttl"`
	MaxLeaseTtl string `json:"max_lease_ttl"`
	ForceNoCache bool `json:"force_no_cache"`
}

type GithubAuthRequest struct {
	Type string `json:"type"`
	Local bool `json:"local"`
	SealWrap bool `json:"seal_wrap"`
	ExternalEntropyAccess bool `json:"externl_entropy_access"`
	Options []string `json:"options"`
	Config GithubAuthConfig `json:"config"`
}

type GithubMapTeamRequest struct {
	Team string `json:"team_name"`
	Policies []string `json:"value"`
}

type PolicyCreateRequest struct {
	Policy string `json:"policy"`
}

func mapGithubTeam(key string) (bool, error) {
	return false, nil
}

//
// {"type":"github","description":"","config":{"options":null,"default_lease_ttl":"0s","max_lease_ttl":"0s","force_no_cache":false},"local":false,"seal_wrap":false,"external_entropy_access":false,"options":null}
//
func enableGithubAuth(token string) (bool, error) {
	log.Println("Remove this way before releasing...")
	log.Println(token)

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
	//authRequestResponseBody, err := ioutil.ReadAll(response.Body)
	//if err != nil {
	//	return false, err
	//}

	return true, nil
}

func createPolicy(token string, key string, policy string) (bool, error) {
	policyRequest := PolicyCreateRequest{
		Policy: policy,
	}

	policyRequestData, err := json.Marshal(&policyRequest)
	if err != nil {
		return false, err
	}

	r := bytes.NewReader(policyRequestData)
	request, err := http.NewRequest(http.MethodPut,  vaultAddr+"/v1/sys/policy/"+key, r)

	response, err := httpClient.Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		return false, fmt.Errorf("policy creation: non-200 status code: %d", response.StatusCode)
	}

	return true, nil
}

func InitializeAuth(token string) (bool, error) {
	//res, err := createPolicy(token, "vault_admins", "/policies/admin.hcl")
	//if err != nil {
	//	return false, err
	//}

	_, err := enableGithubAuth(token)
	if err != nil {
		return false, err
	}

	return false, nil
}

