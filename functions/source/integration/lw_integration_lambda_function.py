import json
import logging
import os

import boto3
import cfnresponse

from botocore.exceptions import ClientError
from laceworksdk import LaceworkClient

# Integration Types (https://<myaccount>.lacework.net/api/v1/external/docs)
#   AWS_CFG - Amazon Web Services (AWS) Compliance

LOGLEVEL = os.environ.get('LOGLEVEL', logging.INFO)
logger = logging.getLogger()
logger.setLevel(LOGLEVEL)


def handler(event, context):
    logger.info(event)

    event_message = json.loads(event['Records'][0]['Sns']['Message'])

    request_type = event_message['RequestType']
    role_arn = event_message['ResourceProperties']['RoleArn']
    external_id = event_message['ResourceProperties']['ExternalId']

    logger.info(f'Request Type: {request_type}')
    logger.info(f'Role ARN: {role_arn}')

    lacework_client = get_lacework_client(event_message, context)

    try:
        if request_type == 'Create':
            return on_create(lacework_client, role_arn, external_id, event_message, context)
        elif request_type == 'Update':
            return on_update(lacework_client, role_arn, external_id, event_message, context)
        elif request_type == 'Delete':
            return on_delete(lacework_client, role_arn, event_message, context)
        else:
            raise Exception('Invalid request type: %s' % request_type)
    except Exception as e:
        send_cfn_failure(event, context, 'Generic failure during integration action', e)


def on_create(lacework_client, role_arn, external_id, event, context):
    integtation_prefix = os.environ['LW_INT_PREFIX']

    logger.info('Started creating AWS Config integration')

    try:
        lacework_client.cloud_accounts.create(
            name=f'{integtation_prefix}-Config',
            type='AwsCfg',
            enabled=1,
            data={
                'crossAccountCredentials': {
                    'externalId': external_id,
                    'roleArn': role_arn
                }
            }
        )

        logger.info('Finished creating AWS Config integration')

        # send response back to cfn template that was created by the new stack
        send_cfn_success(event, context)
    except Exception as e:
        send_cfn_failure(event, context, 'Failure during integration creation', e)


def on_update(lacework_client, role_arn, external_id, event, context):
    integration = find_integration(lacework_client, role_arn)

    logger.info('Started updating AWS Config integration')

    if integration:
        try:
            lacework_client.cloud_accounts.update(
                guid=integration['intgGuid'],
                name=integration['name'],
                type=integration['type'],
                enabled=integration['enabled'],
                data={
                    'crossAccountCredentials': {
                        'externalId': external_id,
                        'roleArn': role_arn
                    }
                }
            )

            logger.info('Finished updating AWS Config integration')

            # send response back to cfn template that was created by the new stack
            send_cfn_success(event, context)
        except Exception as error:
            send_cfn_failure(event, context, 'Failure during integration update', error)
    else:
        on_create(lacework_client, role_arn, external_id, event, context)


def on_delete(lacework_client, role_arn, event, context):
    integration = find_integration(lacework_client, role_arn)

    logger.info('Started deleting integration %s', integration["name"])

    try:
        lacework_client.cloud_accounts.delete(guid=integration['intgGuid'])

        logger.info('Finished deleting integration %s', integration["name"])

        send_cfn_success(event, context)
    except Exception as error:
        send_cfn_failure(event, context, 'Failure during integration deletion', error)


def find_integration(lacework_client, role_arn):
    integrations = lacework_client.cloud_accounts.get()['data']

    for integration in integrations:
        if integration['type'] in ('AwsCfg'):
            if integration['data']['crossAccountCredentials']['roleArn'] == role_arn:
                return integration

    return None


def send_cfn_success(event, context):
    new_account_id = event['ResourceProperties']['AccountId']
    responseData = {}
    responseData['data'] = new_account_id
    cfnresponse.send(event, context, cfnresponse.SUCCESS, responseData)


def send_cfn_failure(event, context, message_text, exception=None):
    responseData = {
        'text': message_text,
        'error': str(exception)
    }
    logger.error(responseData)
    cfnresponse.send(event, context, cfnresponse.FAILED, responseData)
    exit()


def get_lacework_client(event, context):

    secret_name = 'LaceworkApiCredentials'
    region_name = os.environ['AWS_REGION']

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

        err_msg = str(e)

        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            err_msg = f'The requested secret {secret_name} was not found'
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            err_msg = f'The request was invalid due to: {err_msg}'
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            err_msg = f'The request had invalid params: {err_msg}'
        elif e.response['Error']['Code'] == 'DecryptionFailure':
            err_msg = f'The secret can\'t be decrypted using the provided KMS key: {err_msg}'
        elif e.response['Error']['Code'] == 'InternalServiceError':
            err_msg = f'An error occurred on service side: {err_msg}'

        send_cfn_failure(event, context, err_msg, e)
    else:
        # Secrets Manager decrypts the secret value using the associated KMS CMK
        # Depending on whether the secret was a string or binary,
        # only one of these fields will be populated
        if 'SecretString' in get_secret_value_response:
            text_secret_data = get_secret_value_response['SecretString']

    try:
        json_secret_data = json.loads(text_secret_data)
        os.environ['LW_API_KEY'] = json_secret_data['AccessKeyID']
        os.environ['LW_API_SECRET'] = json_secret_data['SecretKey']
    except Exception as e:
        send_cfn_failure(event, context, 'Unable to parse secret data stored by CF Template', e)

    try:
        lw_client = LaceworkClient()
    except Exception as e:
        send_cfn_failure(event, context, 'Unable to configure Lacework client', e)

    return lw_client
