package main

import (
	"encoding/json"
	"github.com/aws/aws-lambda-go/events"
	"github.com/flow-lab/dlog"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

const requestID = "1-581cf771-a006649127e371903a2de979"

// Toke will expire ...
// TODO [grokrz]: mock ?
//func TestValid(t *testing.T) {
//	os.Setenv("COGNITO_ID", "eu-west-1_yubvj7uwx")
//	os.Setenv("AWS_REGION", "eu-west-1")
//	var inputJSON = readFile("token-valid.json")
//	var event events.APIGatewayCustomAuthorizerRequest
//	if err := json.Unmarshal(inputJSON, &event); err != nil {
//		assert.FailNow(t, "unable to deserialize", inputJSON)
//	}
//	output, err := Process(event, dlog.NewRequestLogger(requestID, "test"))
//
//	assert.Nil(t, err)
//	assert.NotNil(t, output.PrincipalID)
//}

func TestExpired(t *testing.T) {
	var inputJSON = readFile("token-expired.json")
	var event events.APIGatewayCustomAuthorizerRequest
	if err := json.Unmarshal(inputJSON, &event); err != nil {
		assert.FailNow(t, "unable to deserialize", inputJSON)
	}

	_, err := Process(event, dlog.NewRequestLogger(requestID, "test"))

	assert.Equal(t, "unauthorized", err.Error())
}

func TestInvalid(t *testing.T) {
	var inputJSON = readFile("token-invalid.json")
	var event events.APIGatewayCustomAuthorizerRequest
	if err := json.Unmarshal(inputJSON, &event); err != nil {
		assert.FailNow(t, "unable to deserialize", inputJSON)
	}

	_, err := Process(event, dlog.NewRequestLogger(requestID, "test"))

	assert.Equal(t, "unauthorized", err.Error())
}

func readFile(path string) []byte {
	f, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return f
}
