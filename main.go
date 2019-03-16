package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/dgrijalva/jwt-go"
	"github.com/flow-lab/dlog"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"strings"
)

// Handler for lambda execution
func Handler(ctx context.Context, event events.APIGatewayCustomAuthorizerRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	lambdaContext, _ := lambdacontext.FromContext(ctx)
	requestLogger := dlog.NewRequestLogger(lambdaContext.AwsRequestID, "log-group-retention")
	requestLogger.Infof("client token: %v", event.AuthorizationToken)
	requestLogger.Infof("method ARN: %v", event.MethodArn)
	return Process(event, requestLogger)
}

func Process(event events.APIGatewayCustomAuthorizerRequest, requstLogger *logrus.Entry) (events.APIGatewayCustomAuthorizerResponse, error) {
	token, err := decodeToken(event.AuthorizationToken, requstLogger)
	if err != nil || !token.Valid {
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("unauthorized")
	}

	tmp := strings.Split(event.MethodArn, ":")
	apiGatewayArnTmp := strings.Split(tmp[5], "/")
	awsAccountID := tmp[4]

	principalId := token.Claims.(*CognitoClaims).Sub
	resp := NewAuthorizerResponse(principalId, awsAccountID)
	resp.Region = tmp[3]
	resp.APIID = apiGatewayArnTmp[0]
	resp.Stage = apiGatewayArnTmp[1]
	resp.DenyAllMethods()

	requstLogger.Debugf("response: %v", resp)
	return resp.APIGatewayCustomAuthorizerResponse, nil
}

// https://cognito-idp.<region>.amazonaws.com/<cognito-id>/.well-known/jwks.json
type Jwks struct {
	Keys []Key `json:"keys"`
}

type Key struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type CognitoClaims struct {
	Sub string `json:"sub"`
	jwt.StandardClaims
}

func decodeToken(tokenString string, log *logrus.Entry) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CognitoClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			err := fmt.Errorf("unknown signing method: %v", token.Header["alg"])
			log.Error(err.Error())
			return nil, err
		}
		k := getKey(token.Header["kid"].(string), log)
		rsaPublicKey, err := mapToRSAPublicKey(k.E, k.N)
		return rsaPublicKey, err
	})

	return token, err
}

// https://gist.github.com/MathieuMailhos/361f24316d2de29e8d41e808e0071b13
func mapToRSAPublicKey(encodedE, encodedN string) (*rsa.PublicKey, error) {
	decodedE, err := base64.RawURLEncoding.DecodeString(encodedE)
	if err != nil {
		return nil, err
	}
	if len(decodedE) < 4 {
		ndata := make([]byte, 4)
		copy(ndata[4-len(decodedE):], decodedE)
		decodedE = ndata
	}
	pubKey := &rsa.PublicKey{
		N: &big.Int{},
		E: int(binary.BigEndian.Uint32(decodedE[:])),
	}
	decodedN, err := base64.RawURLEncoding.DecodeString(encodedN)
	if err != nil {
		panic(err)
	}
	pubKey.N.SetBytes(decodedN)
	return pubKey, nil
}

func getKey(kid string, log *logrus.Entry) Key {
	log.Debugf("about to find Key for: %s", kid)
	var inputJSON = getKeyJwks(log)
	var jwkss Jwks
	json.Unmarshal(inputJSON, &jwkss)

	for _, j := range jwkss.Keys {
		if j.Kid == kid {
			log.Debugf("found %s", kid)
			return j
		}
	}

	return Key{}
}

func getKeyJwks(log *logrus.Entry) []byte {
	// TODO [grokrz]: fail fast if not found
	cognitoId := os.Getenv("COGNITO_ID")
	awsRegion := os.Getenv("AWS_REGION")
	url := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", awsRegion, cognitoId)
	log.Debugf("about to fetch: %s", url)
	response, e := http.Get(url)
	if e != nil || response.StatusCode != 200 {
		// TODO [grokrz[: fail
		log.Fatal(e)
	}
	jwksStr, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		log.Fatal(err)
	}

	return jwksStr
}

type HttpVerb int

const (
	Get HttpVerb = iota
	Post
	Put
	Delete
	Patch
	Head
	Options
	All
)

func (hv HttpVerb) String() string {
	switch hv {
	case Get:
		return "GET"
	case Post:
		return "POST"
	case Put:
		return "PUT"
	case Delete:
		return "DELETE"
	case Patch:
		return "PATCH"
	case Head:
		return "HEAD"
	case Options:
		return "OPTIONS"
	case All:
		return "*"
	}
	return ""
}

type Effect int

const (
	Allow Effect = iota
	Deny
)

func (e Effect) String() string {
	switch e {
	case Allow:
		return "Allow"
	case Deny:
		return "Deny"
	}
	return ""
}

type AuthorizerResponse struct {
	events.APIGatewayCustomAuthorizerResponse

	// The region where the API is deployed. By default this is set to '*'
	Region string

	// The AWS account id the policy will be generated for. This is used to create the method ARNs.
	AccountID string

	// The API Gateway API id. By default this is set to '*'
	APIID string

	// The name of the stage used in the policy. By default this is set to '*'
	Stage string
}

func NewAuthorizerResponse(principalID string, AccountID string) *AuthorizerResponse {
	return &AuthorizerResponse{
		APIGatewayCustomAuthorizerResponse: events.APIGatewayCustomAuthorizerResponse{
			PrincipalID: principalID,
			PolicyDocument: events.APIGatewayCustomAuthorizerPolicy{
				Version: "2012-10-17",
			},
		},
		Region:    "*",
		AccountID: AccountID,
		APIID:     "*",
		Stage:     "*",
	}
}

func (r *AuthorizerResponse) addMethod(effect Effect, verb HttpVerb, resource string) {
	resourceArn := "arn:aws:execute-api:" +
		r.Region + ":" +
		r.AccountID + ":" +
		r.APIID + "/" +
		r.Stage + "/" +
		verb.String() + "/" +
		strings.TrimLeft(resource, "/")

	s := events.IAMPolicyStatement{
		Effect:   effect.String(),
		Action:   []string{"execute-api:Invoke"},
		Resource: []string{resourceArn},
	}

	r.PolicyDocument.Statement = append(r.PolicyDocument.Statement, s)
}

func (r *AuthorizerResponse) AllowAllMethods() {
	r.addMethod(Allow, All, "*")
}

func (r *AuthorizerResponse) DenyAllMethods() {
	r.addMethod(Deny, All, "*")
}

func (r *AuthorizerResponse) AllowMethod(verb HttpVerb, resource string) {
	r.addMethod(Allow, verb, resource)
}

func (r *AuthorizerResponse) DenyMethod(verb HttpVerb, resource string) {
	r.addMethod(Deny, verb, resource)
}

func main() {
	lambda.Start(Handler)
}
