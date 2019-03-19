# lambda-authorizer
Amazon API Gateway Lambda Authorizer

* validates id token against cognito public keys
* supports multiple cognito ids

Lambda env parameters:
* `COGNITO_IDS` - cognito ids separeted with ",", eg. "u-west-1_yubvj7uwx,eu-west-1_ybbsjdf8f"
* `AWS_REGION` - aws region, eg. "eu-west-1"
