import json
import logging
import os

import boto3
import cfnresponse

from botocore.exceptions import ClientError
from laceworksdk import LaceworkClient

logging.basicConfig(
    format='%(asctime)s %(name)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger('lacework-integration-setup')
logger.setLevel(os.getenv('LOG_LEVEL', logging.INFO))


def handler(event, context):
    logger.info(event)

    event_message = json.loads(event['Records'][0]['Sns']['Message'])

    request_type = event_message['RequestType']
    role_arn = event_message['ResourceProperties']['RoleArn']
    external_id = event_message['ResourceProperties']['ExternalId']

    logger.info('Request Type: %s', request_type)
    logger.info('Role ARN: %s', role_arn)

    lacework_client = get_lacework_client(event_message, context)

    try:
        if request_type == 'Create':
            on_create(lacework_client, role_arn, external_id, event_message, context)
        elif request_type == 'Update':
            on_update(lacework_client, role_arn, external_id, event_message, context)
        elif request_type == 'Delete':
            on_delete(lacework_client, role_arn, external_id, event_message, context)
        else:
            raise Exception(f'Invalid request type: {request_type}')
    except Exception as error:
        send_cfn_failure(event, context, 'Generic failure during integration action', error)


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
    except Exception as error:
        send_cfn_failure(event, context, 'Failure during integration creation', error)


def on_update(lacework_client, role_arn, external_id, event, context):
    old_role_arn = event['OldResourceProperties']['RoleArn']
    old_external_id = event['OldResourceProperties']['ExternalId']

    integration = find_integration(lacework_client, old_role_arn, old_external_id)

    if integration:
        logger.info('Started updating AWS Config integration %s', integration['intgGuid'])

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

            logger.info('Finished updating AWS Config integration %s', integration['intgGuid'])

            # send response back to cfn template that was created by the new stack
            send_cfn_success(event, context)
        except Exception as error:
            send_cfn_failure(event, context, 'Failure during integration update', error)
    else:
        logger.info('No existing AWS Config integration was found for the update request.')
        send_cfn_success(event, context)


def on_delete(lacework_client, role_arn, external_id, event, context):
    integration = find_integration(lacework_client, role_arn, external_id)

    if integration:
        logger.info('Started deleting AWS Config integration %s', integration['intgGuid'])

        try:
            lacework_client.cloud_accounts.delete(guid=integration['intgGuid'])

            logger.info('Finished deleting AWS Config integration %s', integration['intgGuid'])

            send_cfn_success(event, context)
        except Exception as error:
            send_cfn_failure(event, context, 'Failure during integration deletion', error)
    else:
        logger.info('No existing AWS Config integration was found for the deletion request.')
        send_cfn_success(event, context)


def find_integration(lacework_client, role_arn, external_id):
    integrations = lacework_client.cloud_accounts.get_by_type('AwsCfg')['data']

    for integration in integrations:
        if integration['type'] in ('AwsCfg'):
            if (integration['data']['crossAccountCredentials']['roleArn'] == role_arn and
               integration['data']['crossAccountCredentials']['externalId'] == external_id):
                return integration

    return None


def send_cfn_success(event, context):
    new_account_id = event['ResourceProperties']['AccountId']
    response_data = {}
    response_data['data'] = new_account_id
    cfnresponse.send(event, context, cfnresponse.SUCCESS, response_data)


def send_cfn_failure(event, context, message_text, exception=None):
    response_data = {
        'text': message_text,
        'error': str(exception)
    }
    logger.error(response_data)
    cfnresponse.send(event, context, cfnresponse.FAILED, response_data)


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
    except ClientError as error:

        err_msg = str(error)

        if error.response['Error']['Code'] == 'ResourceNotFoundException':
            err_msg = f'The requested secret {secret_name} was not found'
        elif error.response['Error']['Code'] == 'InvalidRequestException':
            err_msg = f'The request was invalid due to: {err_msg}'
        elif error.response['Error']['Code'] == 'InvalidParameterException':
            err_msg = f'The request had invalid params: {err_msg}'
        elif error.response['Error']['Code'] == 'DecryptionFailure':
            err_msg = f'The secret can\'t be decrypted using the provided KMS key: {err_msg}'
        elif error.response['Error']['Code'] == 'InternalServiceError':
            err_msg = f'An error occurred on service side: {err_msg}'

        send_cfn_failure(event, context, err_msg, error)
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
    except Exception as error:
        send_cfn_failure(event, context, 'Unable to parse secret data stored by CF Template', error)

    try:
        lw_client = LaceworkClient()
    except Exception as error:
        send_cfn_failure(event, context, 'Unable to configure Lacework client', error)

    return lw_client
