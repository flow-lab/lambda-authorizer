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

func TestUnauthenticated(t *testing.T) {
	var inputJSON = readFile("token-unauthenticated.json")
	var event events.APIGatewayCustomAuthorizerRequest
	if err := json.Unmarshal(inputJSON, &event); err != nil {
		assert.FailNow(t, "unable to deserialize", inputJSON)
	}

	_, err := Process(event, dlog.NewRequestLogger(requestID, "test"))

	assert.NotNil(t, err)
}

func readFile(path string) []byte {
	f, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return f
}
