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
	requestLogger := dlog.NewRequestLogger(lambdaContext.AwsRequestID, "lambda-authorizer")
	requestLogger.Infof("method ARN: %v", event.MethodArn)
	return Process(event, requestLogger)
}

func Process(event events.APIGatewayCustomAuthorizerRequest, log *logrus.Entry) (events.APIGatewayCustomAuthorizerResponse, error) {
	token, err := decodeToken(event.AuthorizationToken, log)
	if !validate(token, err, log) {
		log.Debug("unauthorized. Token is not valid")
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

	log.Debugf("response: %v", resp)
	return resp.APIGatewayCustomAuthorizerResponse, nil
}

func validate(token *jwt.Token, err error, log *logrus.Entry) bool {
	if err != nil {
		log.Debugf("token use is not valid, err: %v", err)
		return false
	}

	if !token.Valid {
		log.Debugf("token use is not valid")
		return false
	}

	if token.Claims.(*CognitoClaims).TokenUse != "id" {
		log.Debugf("token use is not 'id', only id Token kan be authorized")
		return false
	}

	return true
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
	Sub      string `json:"sub"`
	TokenUse string `json:"token_use"`
	jwt.StandardClaims
}

func decodeToken(tokenString string, log *logrus.Entry) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CognitoClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			err := fmt.Errorf("unknown signing method: %v", token.Header["alg"])
			log.Error(err.Error())
			return nil, err
		}
		k, err := getKey(token.Header["kid"].(string), log)
		if err != nil {
			return nil, err
		}
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

func getKey(kid string, log *logrus.Entry) (Key, error) {
	log.Debugf("about to find Key for: %s", kid)
	var err error
	if j, err := getKeyJwks(log); err == nil {
		for _, jwks := range j {
			for _, j := range jwks.Keys {
				if j.Kid == kid {
					log.Debugf("found %s", kid)
					return j, nil
				}
			}
		}
	}

	return Key{}, fmt.Errorf("key not found. error: %v", err)
}

func getKeyJwks(log *logrus.Entry) ([]*Jwks, error) {
	cognitoIds := parseIds(os.Getenv("COGNITO_IDS"))
	if len(cognitoIds) < 1 {
		return nil, fmt.Errorf("COGNITO_IDS cannot be empty")
	}
	awsRegion := os.Getenv("AWS_REGION")
	if awsRegion == "" {
		return nil, fmt.Errorf("AWS_REGION cannot be empty")
	}

	var jwkss []*Jwks
	for _, cognitoId := range cognitoIds {
		url := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", awsRegion, cognitoId)
		log.Debugf("about to get: %s", url)
		response, err := http.Get(url)
		if err != nil || response.StatusCode != 200 {
			log.Errorf("unable to get jwks, err: %v", err)
			return nil, err
		}
		jwksByteArr, err := ioutil.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			log.Errorf("unable to read the body, err: %v", err)
			return nil, err
		}

		var jwks Jwks
		json.Unmarshal(jwksByteArr, &jwks)
		jwkss = append(jwkss, &jwks)
	}

	return jwkss, nil
}

func parseIds(s string) []string {
	arr := strings.Split(s, ",")
	return filter(arr, func(v string) bool {
		return v != ""
	})
}

func filter(vs []string, f func(string) bool) []string {
	vsf := make([]string, 0)
	for _, v := range vs {
		if f(v) {
			vsf = append(vsf, v)
		}
	}
	return vsf
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
