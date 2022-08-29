package cliClient

import (
	"encoding/json"
	"net/http"

	"github.com/datreeio/datree/bl/files"
)

type PublishFailedRequestBody struct {
	File   files.UnknownStruct `json:"file"`
	Policy string              `json:"policy"`
}

func (c *CliClient) PublishRemediation(remediationConfig PublishFailedRequestBody, token string) (*PublishFailedResponse, error) {
	res, publishErr := c.httpClient.Request(http.MethodPut, "/cli/remedation/tokens/"+token, remediationConfig, map[string]string{})
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

func (c *CliClient) GetRemediationConfig() (interface{}, error) {
	return nil, nil
}
