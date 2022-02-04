from laceworksdk import LaceworkClient
import boto3
from botocore.exceptions import ClientError
import os
import json
import cfnresponse
import ast

# Integration Types (https://<myaccount>.lacework.net/api/v1/external/docs)
#   AWS_CFG - Amazon Web Services (AWS) Compliance


def handler(event, context):
    if 'Records' in event:
        for record in event['Records']:
            event_message = ast.literal_eval(record['Sns']['Message'])
            print("Message: ")
            print(event_message)
            request_type = event_message['RequestType']
            print(request_type)
            role_arn = event_message['ResourceProperties']['RoleArn']
            print(role_arn)
            external_id = event_message['ResourceProperties']['ExternalId']
    else:
        request_type = event['RequestType']
        role_arn = event['ResourceProperties']['RoleArn']
        external_id = event['ResourceProperties']['ExternalId']
    
    try:
        lacework_client = get_lacework_client(event_message, context)
    except Exception as e:
        responseData ={"text": "Unable to create Lacework client",
                        "error": str(e)} 
        print(responseData)
        cfnresponse.send(event_message, context, cfnresponse.FAILED, responseData)

    try:
        if request_type == 'Create':
            return on_create(lacework_client, role_arn, external_id, event_message, context)
        elif request_type == 'Update':
            return on_update(lacework_client, role_arn, external_id, event_message, context)
        elif request_type == 'Delete':
            return on_delete(lacework_client, role_arn, event_message, context)
        else:
            raise Exception("Invalid request type: %s" % request_type)
    except Exception as e:
        responseData ={"text": "Generic failure during integration action.",
                        "error": str(e)} 
        print(responseData)
        cfnresponse.send(event_message, context, cfnresponse.FAILED, responseData)


def on_create(lacework_client, role_arn, external_id, event, context):
    environment = os.environ['ENVIRONMENT']

    print("Started creating AWS Config integration")
    print(external_id)
    print(role_arn)
    try:
        lacework_client.integrations.create(
            name=f"{environment}-Config",
            type='AWS_CFG',
            enabled=1,
            data={
                "CROSS_ACCOUNT_CREDENTIALS": {
                    "EXTERNAL_ID": external_id,
                    "ROLE_ARN": role_arn
                }
            }
        )
        print("Finished creating AWS Config integration")
        #send response back to cfn template that was created by the new stack
        new_account_id = event['ResourceProperties']['AccountId']
        responseData = {}
        responseData['account_id'] = new_account_id
        cfnresponse.send(event, context, cfnresponse.SUCCESS, responseData)

    except Exception as e:
        responseData = {"text": "Failure during integration creation.", "error": str(e)}
        print(responseData)
        cfnresponse.send(event, context, cfnresponse.FAILED, responseData)


def on_update(lacework_client, role_arn, external_id, event, context):
    integration = find_integration(lacework_client, role_arn, event, context)

    print("Started updating AWS Config integration")
    try:
        lacework_client.integrations.update(
            guid=integration['INTG_GUID'],
            name=integration['NAME'],
            type='AWS_CFG',
            enabled=integration['ENABLED'],
            data={
                "CROSS_ACCOUNT_CREDENTIALS": {
                    "EXTERNAL_ID": external_id,
                    "ROLE_ARN": role_arn
                }
            }
        )

        print("Finished updating AWS Config integration")
        #send response back to cfn template that was created by the new stack
        new_account_id = event['ResourceProperties']['AccountId']
        responseData = {}
        responseData['data'] = new_account_id
        cfnresponse.send(event, context, cfnresponse.SUCCESS, responseData)
    except Exception as e:
        responseData = {"text": "Failure during integration update.", "error": str(e)}
        print(responseData)
        cfnresponse.send(event, context, cfnresponse.FAILED, responseData)


def on_delete(lacework_client, role_arn, event, context):
    integration = find_integration(lacework_client, role_arn, event, context)

    print(f"started deleting integration {integration['NAME']}")
    try:
        lacework_client.integrations.delete(guid=integration['INTG_GUID'])
        new_account_id = event['ResourceProperties']['AccountId']
        responseData = {}
        responseData['data'] = new_account_id
        cfnresponse.send(event, context, cfnresponse.SUCCESS, responseData)
        print(f"Finished deleting integration {integration['NAME']}")
    except Exception as e:
        responseData = {"text": "Failure during integration deletion.", "error": str(e)}
        print(responseData)
        cfnresponse.send(event, context, cfnresponse.FAILED, responseData)


def find_integration(lacework_client, role_arn, event, context):
    integrations = lacework_client.integrations.get()['data']

    for integration in integrations:
        if integration['TYPE'] in ('AWS_CFG'):
            if (integration['DATA']['CROSS_ACCOUNT_CREDENTIALS']['ROLE_ARN']
                    == role_arn):
                return integration

    print("Failure while finding integration.")
    cfnresponse.send(event, context, cfnresponse.FAILED, responseData={"text": "Find integration failure"})
    raise Exception(
        f"no existing integration found for role arn: {role_arn}"
    )


def get_lacework_client(event, context):

    secret_name = "LaceworkApiCredentials"
    region_name = "us-east-1"

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name,
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print("The requested secret " + secret_name + " was not found")
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            print("The request was invalid due to:", e)
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            print("The request had invalid params:", e)
        elif e.response['Error']['Code'] == 'DecryptionFailure':
            print("The requested secret can't be decrypted using the provided KMS key:", e)
        elif e.response['Error']['Code'] == 'InternalServiceError':
            print("An error occurred on service side:", e)
        cfnresponse.send(event, context, cfnresponse.FAILED, responseData={"error": str(e)})
    else:
        # Secrets Manager decrypts the secret value using the associated KMS CMK
        # Depending on whether the secret was a string or binary, only one of these fields will be populated
        if 'SecretString' in get_secret_value_response:
            text_secret_data = get_secret_value_response['SecretString']
        else:
            binary_secret_data = get_secret_value_response['SecretBinary']
        # Your code goes here.
    try:
        account = os.environ['LW_ACCOUNT']
    except Exception as e:
        responseData = { "text": "Unable to pull environment variable in Lambda function",
                        "error": str(e)}
        print(responseData)
        cfnresponse.send(event, context, cfnresponse.FAILED, responseData)

    try:
        json_secret_data = json.loads(text_secret_data)
        api_key = json_secret_data['AccessKeyID']
        api_secret = json_secret_data['SecretKey']
    except Exception as e:
        responseData ={"text": "Unable to parse secret data stored by CF Template",
                        "error": str(e)} 
        print(responseData)
        cfnresponse.send(event, context, cfnresponse.FAILED, responseData)
 
    return LaceworkClient(account=account, api_key=api_key, api_secret=api_secret) 

