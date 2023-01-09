import json
import logging
import os

import boto3
import cfnresponse
import requests

from botocore.exceptions import ClientError
from laceworksdk import LaceworkClient, ApiError

HONEY_API_KEY = "$HONEY_KEY"
DATASET = "$DATASET"
BUILD_VERSION = "$BUILD"

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
    account_id = event_message['ResourceProperties']['AccountId']

    logger.info('Request Type: %s', request_type)
    logger.info('Role ARN: %s', role_arn)

    lacework_client = get_lacework_client(event_message, context)

    try:
        if request_type == 'Create':
            on_create(lacework_client, role_arn, external_id, account_id, event_message, context)
        elif request_type == 'Update':
            on_update(lacework_client, role_arn, external_id, account_id, event_message, context)
        elif request_type == 'Delete':
            on_delete(lacework_client, role_arn, external_id, account_id, event_message, context)
        else:
            raise Exception(f'Invalid request type: {request_type}')
    except Exception as error:
        send_cfn_failure(event, context, 'Generic failure during integration action', error)


def on_create(lacework_client, role_arn, external_id, account_id, event, context):
    integration_prefix = os.environ['LW_INT_PREFIX']
    lw_account = os.environ['LW_ACCOUNT']

    logger.info('Started creating AWS Config integration for account ID %s', account_id)
    send_honeycomb_event(HONEY_API_KEY, DATASET, BUILD_VERSION, lw_account, "create started",
                         "", get_lacework_environment_variables())

    try:
        lacework_client.cloud_accounts.create(
            name=f'{integration_prefix}-Config',
            type='AwsCfg',
            enabled=1,
            data={
                'awsAccountId': account_id,
                'crossAccountCredentials': {
                    'externalId': external_id,
                    'roleArn': role_arn
                }
            }
        )

        logger.info('Finished creating AWS Config integration')

        send_honeycomb_event(HONEY_API_KEY, DATASET, BUILD_VERSION, lw_account, "create complete",
                             "", get_lacework_environment_variables())

        # send response back to cfn template that was created by the new stack
        send_cfn_success(event, context)
    except ApiError as apiError:
        if 'aws account is already used' in apiError.message:
            logger.warning("Account is already in use. Skipping. %s", apiError)
        else:
            send_cfn_failure(event, context, 'Error from Lacework API', apiError)
    except Exception as error:
        send_cfn_failure(event, context, 'Failure during integration creation', error)


def on_update(lacework_client, role_arn, external_id, account_id, event, context):
    old_role_arn = event['OldResourceProperties']['RoleArn']
    old_external_id = event['OldResourceProperties']['ExternalId']
    lw_account = os.environ['LW_ACCOUNT']
    send_honeycomb_event(HONEY_API_KEY, DATASET, BUILD_VERSION, lw_account, "update started",
                         "", get_lacework_environment_variables())

    integration = find_integration(lacework_client, old_role_arn, old_external_id)

    if integration:
        logger.info('Started updating AWS Config integration %s and account ID %s', integration['intgGuid'], account_id)

        try:
            lacework_client.cloud_accounts.update(
                guid=integration['intgGuid'],
                name=integration['name'],
                type=integration['type'],
                enabled=integration['enabled'],
                data={
                    'awsAccountId': account_id,
                    'crossAccountCredentials': {
                        'externalId': external_id,
                        'roleArn': role_arn
                    }
                }
            )

            logger.info('Finished updating AWS Config integration %s', integration['intgGuid'])
            send_honeycomb_event(HONEY_API_KEY, DATASET, BUILD_VERSION, lw_account, "update complete",
                                 "", get_lacework_environment_variables())
            # send response back to cfn template that was created by the new stack
            send_cfn_success(event, context)
        except Exception as error:
            send_cfn_failure(event, context, 'Failure during integration update', error)
    else:
        logger.info('No existing AWS Config integration was found for the update request.')
        send_cfn_success(event, context)


def on_delete(lacework_client, role_arn, external_id, event, context):
    integration = find_integration(lacework_client, role_arn, external_id)
    lw_account = os.environ['LW_ACCOUNT']
    send_honeycomb_event(HONEY_API_KEY, DATASET, BUILD_VERSION, lw_account, "delete started",
                         "", get_lacework_environment_variables())
    if integration:
        logger.info('Started deleting AWS Config integration %s', integration['intgGuid'])

        try:
            lacework_client.cloud_accounts.delete(guid=integration['intgGuid'])

            logger.info('Finished deleting AWS Config integration %s', integration['intgGuid'])
            send_honeycomb_event(HONEY_API_KEY, DATASET, BUILD_VERSION, lw_account, "delete complete",
                                 "", get_lacework_environment_variables())
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


def send_honeycomb_event(honey_key, dataset, version, account, event, subaccount="000000", eventdata="{}"):
    logger.info("honeycomb.send_honeycomb_event called.")

    try:
        payload = '''
        {{
            "account": "{}",
            "sub-account": "{}",
            "tech-partner": "AWS",
            "integration-name": "aws-org-cf-lacework",
            "version": "{}",
            "service": "AWS CloudFormation",
            "install-method": "cloudformation",
            "function": "lw_integration_lambda_function.py",
            "event": "{}",
            "event-data": {}
        }}
        '''.format(account, subaccount, version, event, eventdata)
        logger.info('Generate payload : {}'.format(payload))
        resp = requests.post("https://api.honeycomb.io/1/events/" + dataset,
                             headers={'X-Honeycomb-Team': honey_key,
                                      'content-type': 'application/json'},
                             verify=True, data=payload)
        logger.info("Honeycomb response {} {}".format(resp, resp.content))

    except Exception as e:
        logger.warning("Get error sending to Honeycomb: {}.".format(e))


def get_lacework_environment_variables():
    env_vars = {}
    for key, value in os.environ.items():
        if key.startswith("lacework"):
            env_vars[key] = value

    return json.dumps(env_vars)
