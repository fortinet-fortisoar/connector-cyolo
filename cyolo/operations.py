""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import json
import requests
from connectors.core.connector import get_logger, ConnectorError
from .constants import *

logger = get_logger('cyolo')


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


def get_users_list(config, params):
    endpoint = "users"
    return make_api_call(endpoint=endpoint, config=config)


def get_user_policy(config, params):
    endpoint = f"users/{params.get('id')}/policies"
    return make_api_call(endpoint=endpoint, config=config)


def get_user_by_id_or_name(config, params):
    endpoint = f"users/{params.get('id')}"
    return make_api_call(endpoint=endpoint, config=config)


def delete_user_by_id_or_name(config, params):
    endpoint = f"users/{params.get('id')}"
    response = make_api_call(method='DELETE', endpoint=endpoint, config=config)
    if response:
        return {'status': 'success', 'result': 'User successfully Deleted'}


def get_policy_list(config, params):
    endpoint = "policies"
    return make_api_call(endpoint=endpoint, config=config)


def get_policy_by_id_or_name(config, params):
    endpoint = f"policies/{params.get('id')}"
    return make_api_call(endpoint=endpoint, config=config)


def get_simple_group_list(config, params):
    endpoint = "simple_group"
    return make_api_call(endpoint=endpoint, config=config)


def _check_health(config):
    try:
        params = {}
        get_users_list(config, params)
        return True
    except Exception as e:
        logger.error("Invalid Credentials: %s" % str(e))
        raise ConnectorError("Invalid Credentials")


operations = {
    'get_users_list': get_users_list,
    'get_user_policy': get_user_policy,
    'get_user_by_id_or_name': get_user_by_id_or_name,
    'delete_user_by_id_or_name': delete_user_by_id_or_name,
    'get_policy_list': get_policy_list,
    'get_policy_by_id_or_name': get_policy_by_id_or_name,
    'get_simple_group_list': get_simple_group_list
}
