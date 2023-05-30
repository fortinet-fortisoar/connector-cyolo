""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import json
import requests
from connectors.core.connector import get_logger, ConnectorError
from datetime import datetime

logger = get_logger('cyolo')

param_list = ['mappings', 'supervisors', 'users', 'simple_groups', 'dynamic_groups', 'webhooks',
              'mapping_categories', 'trusted_certificates', 'device_posture_profiles']

day_list = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']


def make_api_call(method="GET", endpoint="", config=None, params=None, data=None, json_data=None):
    try:
        headers = {
            "accept": "application/json",
            'Authorization': f"Basic {config.get('api_key')}"
        }
        server_url = config.get('server_url')
        if not server_url.startswith('https://') and not server_url.startswith('http://'):
            server_url = "https://" + server_url
        url = server_url + '/v1/' + endpoint
        response = requests.request(method=method, url=url,
                                    headers=headers, data=data, json=json_data, params=params,
                                    verify=config.get('verify_ssl'))
        if response.ok:
            try:
                return response.json()
            except:
                return response
        else:
            if response.text != "":
                err_resp = response.json()
                failure_msg = err_resp['error']
                error_msg = 'Response [{0}:{1} Details: {2}]'.format(response.status_code, response.reason,
                                                                     failure_msg if failure_msg else '')
            else:
                error_msg = 'Response [{0}:{1}]'.format(response.status_code, response.reason)
            logger.error(error_msg)
            raise ConnectorError(error_msg)
    except requests.exceptions.SSLError:
        logger.error('An SSL error occurred')
        raise ConnectorError('An SSL error occurred')
    except requests.exceptions.ConnectionError:
        logger.error('A connection error occurred')
        raise ConnectorError('A connection error occurred')
    except requests.exceptions.Timeout:
        logger.error('The request timed out')
        raise ConnectorError('The request timed out')
    except requests.exceptions.RequestException:
        logger.error('There was an error while handling the request')
        raise ConnectorError('There was an error while handling the request')
    except Exception as err:
        raise ConnectorError(str(err))


def list_users(config, params):
    endpoint = "users"
    return make_api_call(endpoint=endpoint, config=config)


def list_user_policies(config, params):
    endpoint = f"users/{params.get('id')}/policies"
    return make_api_call(endpoint=endpoint, config=config)


def update_policy(config, params):
    endpoint = f"policies/{params.pop('id')}"
    params = build_policy_payload(params)
    params['timed_access'] = {
        "enabled": params.pop('timed_access_status', False),
        "start": handle_date(params.pop('start')) if params.get('start') else "00:00",
        "end": handle_date(params.pop('end')) if params.get('end') else "00:00",
        "days": [True if x in str(params.get('days')) else False for x in day_list]
    }
    params.pop('days', "")
    logger.error(f"payload is {params}")
    response = make_api_call(method='POST', endpoint=endpoint, config=config, data=json.dumps(params))
    if response:
        return {"status": "Successfully Updated"}


def get_user_by_id_or_name(config, params):
    endpoint = f"users/{params.get('id')}"
    return make_api_call(endpoint=endpoint, config=config)


def delete_user_by_id_or_name(config, params):
    endpoint = f"users/{params.get('id')}"
    response = make_api_call(method='DELETE', endpoint=endpoint, config=config)
    if response:
        return {'status': 'success', 'result': 'User successfully Deleted'}


def list_policies(config, params):
    endpoint = "policies"
    return make_api_call(endpoint=endpoint, config=config)


def get_policy_by_id_or_name(config, params):
    endpoint = f"policies/{params.get('id')}"
    return make_api_call(endpoint=endpoint, config=config)


def list_simple_groups(config, params):
    endpoint = "simple_group"
    return make_api_call(endpoint=endpoint, config=config)


def list_dynamic_groups(config, params):
    endpoint = "dynamic_group"
    return make_api_call(endpoint=endpoint, config=config)


def list_constraints(config, params):
    endpoint = "constraints"
    return make_api_call(endpoint=endpoint, config=config)


def list_capabilities(config, params):
    endpoint = "capabilities"
    return make_api_call(endpoint=endpoint, config=config)


def list_mappings(config, params):
    endpoint = "mappings"
    return make_api_call(endpoint=endpoint, config=config)


def list_device_posture_profiles(config, params):
    endpoint = "device_posture_profiles"
    return make_api_call(endpoint=endpoint, config=config)


def list_mapping_categories(config, params):
    endpoint = "mapping_category"
    return make_api_call(endpoint=endpoint, config=config)


def list_mapping_categories(config, params):
    endpoint = "mapping_category"
    return make_api_call(endpoint=endpoint, config=config)


def list_webhooks(config, params):
    endpoint = "webhooks"
    return make_api_call(endpoint=endpoint, config=config)


def list_certificates(config, params):
    endpoint = "webhooks"
    return make_api_call(endpoint=endpoint, config=config)


def build_policy_payload(params):
    params = {k: v for k, v in params.items() if v is not None and v != ''}
    for x in param_list:
        if params.get(x):
            if isinstance(params.get(x), list):
                params[x] = [str(item) for item in params.get(x)]
            else:
                params[x] = [x.strip() for x in str(params.get(x)).split(",")]
    return params


def handle_date(str_date):
    return datetime.strptime(str_date, "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%H:%M")


def create_policy(config, params):
    endpoint = "policies"
    params = build_policy_payload(params)
    params['timed_access'] = {
        "enabled": params.pop('timed_access_status', False),
        "start": handle_date(params.pop('start')) if params.get('start') else "00:00",
        "end": handle_date(params.pop('end')) if params.get('end') else "00:00",
        "days": [True if x in str(params.get('days')) else False for x in day_list]
    }
    params.pop('days', "")
    logger.error(f"payload is {params}")
    return make_api_call(method='PUT', endpoint=endpoint, config=config, data=json.dumps(params))


def _check_health(config):
    try:
        list_users(config, params={})
        return True
    except Exception as e:
        logger.error("Invalid Credentials: %s" % str(e))
        raise ConnectorError("Invalid Credentials")


operations = {
    'list_users': list_users,
    'list_user_policies': list_user_policies,
    'get_user_by_id_or_name': get_user_by_id_or_name,
    'delete_user_by_id_or_name': delete_user_by_id_or_name,
    'list_policies': list_policies,
    'get_policy_by_id_or_name': get_policy_by_id_or_name,
    'list_simple_groups': list_simple_groups,
    'list_dynamic_groups': list_dynamic_groups,
    'list_constraints': list_constraints,
    'list_capabilities': list_capabilities,
    'list_mappings': list_mappings,
    'list_webhooks': list_webhooks,
    'list_device_posture_profiles': list_device_posture_profiles,
    'list_mapping_categories': list_mapping_categories,
    'list_certificates': list_certificates,
    'create_policy': create_policy,
    'update_policy': update_policy
}
