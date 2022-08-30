package cliClient

import (
	"encoding/json"
	"net/http"

	"github.com/datreeio/datree/bl/files"
)

type PublishFailedRequestBody struct {
	File       files.UnknownStruct `json:"file"`
	PolicyName string              `json:"policy_name"`
}

type JsonPatch struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value"`
}

type RemediationConfig map[string]map[string]JsonPatch

func (c *CliClient) PublishRemediation(remediationConfig PublishFailedRequestBody, token string) (*PublishFailedResponse, error) {
	res, publishErr := c.httpClient.Request(http.MethodPut, "/cli/remediation/tokens/"+token, remediationConfig, map[string]string{})
	if publishErr != nil {
		if res.StatusCode != 0 {
			publishFailedResponse := &PublishFailedResponse{}
			err := json.Unmarshal(res.Body, publishFailedResponse)
			if err != nil {
				return nil, publishErr
			}
			return publishFailedResponse, publishErr
		}
		return nil, publishErr
	}
	return nil, nil
}

func (c *CliClient) GetRemediationConfig(token string, policyName string) (*RemediationConfig, error) {
	res, requestError := c.httpClient.Request(http.MethodGet, "/cli/remediation/tokens/"+token+"?policy_name=", interface{}(nil), map[string]string{})
	if requestError != nil {
		return nil, requestError
	}

	if res.StatusCode == 0 {
		return nil, nil
	}

	remediationConfig := &RemediationConfig{}
	err := json.Unmarshal(res.Body, remediationConfig)
	if err != nil {
		return nil, err
	}

	return remediationConfig, requestError
}
