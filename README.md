# aws-org-cf-lacework
Cloud Formation resources for integrating Lacework with an AWS Organization (NOT using Control Tower)


Installing Python dependencies
`pip install --target ./package requests`

Create deployment package and add the lambda function:
```cd package
zip -r ../LaceworkIntegrationSetup.zip .

cd ..
zip -g LaceworkIntegrationSetup.zip lw_integration_lambda_function.py```
