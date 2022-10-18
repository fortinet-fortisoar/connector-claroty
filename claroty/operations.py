""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests, json
from .constants import *
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('claroty')


class Claroty:

        def __init__(self, config):
            self.server_url = config.get('server_url').strip('/')
            if not self.server_url.startswith('https://') and not self.server_url.startswith('http://'):
                self.server_url = 'https://{0}'.format(self.server_url)

            self.username = config['username']
            self.password = config['password']
            self.verify_ssl = config['verify_ssl']
            self.token = ''

        def str_to_list(self, input_str):
            if isinstance(input_str, str) and len(input_str) > 0:
                return [x.strip() for x in input_str.split(',')]
            elif isinstance(input_str, list):
                return input_str
            elif isinstance(input_str, int):
                return input_str
            else:
                return []

        def generate_token(self):
            try:
                data = {
                    "username": self.username,
                    "password": self.password
                }
                res = self.make_rest_call(endpoint='/auth/authenticate', method='POST', data=json.dumps(data))
                if res.get('token'):
                    self.token = res.get('token')
            except Exception as err:
                raise ConnectorError(str(err))

        def make_rest_call(self, endpoint, method, data=None, params=None, header=None):
            try:
                url = self.server_url + endpoint
                logger.debug("Endpoint URL: {0}".format(url))
                headers = {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
                if header:
                    headers.update(header)
                logger.debug("Headers: {0}".format(headers))
                response = requests.request(method, url, headers=headers, verify=self.verify_ssl, data=data,
                                            params=params)
                logger.debug("Response: {0}".format(response.text))
                if response.ok:
                    logger.info('Successfully got response for url {0}'.format(url))
                    if 'json' in str(response.headers):
                        return response.json()
                    else:
                        return response.content
                else:
                    raise ConnectorError("{0}".format(response.text))
            except requests.exceptions.SSLError:
                raise ConnectorError('SSL certificate validation failed')
            except requests.exceptions.ConnectTimeout:
                raise ConnectorError('The request timed out while trying to connect to the server')
            except requests.exceptions.ReadTimeout:
                raise ConnectorError(
                    'The server did not send any data in the allotted amount of time')
            except requests.exceptions.ConnectionError:
                raise ConnectorError('Invalid endpoint or credentials')
            except Exception as err:
                raise ConnectorError(str(err))


def get_assets(config, params):
    return fetch_data_from_server(config, params, endpoint='/ranger/assets')


def fetch_data_from_server(config, params, endpoint):
    try:
        claroty_obj = Claroty(config)
        claroty_obj.generate_token()
        header = {'Authorization': str(claroty_obj.token)}
        data = {}
        if params.get('filters'):
            data = params.get('filters')
        if params.get('per_page'):
            data['per_page'] = params.get('per_page')
        if params.get('page'):
            data['page'] = params.get('page')
        if params.get('format'):
            data['format'] = params.get('format')
        res = claroty_obj.make_rest_call(endpoint=endpoint, method='GET', params=data, header=header)
        return res
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(err)


def get_asset_details(config, params):
    endpoint = '/ranger/assets/{id}'.format(id=params.get('resource_id'))
    return fetch_data_from_server(config, params, endpoint)


def get_alerts(config, params):
    return fetch_data_from_server(config, params, endpoint='/ranger/alerts')


def get_alert_details(config, params):
    endpoint = '/ranger/alerts/{id}'.format(id=params.get('resource_id'))
    return fetch_data_from_server(config, params, endpoint)


def get_tasks(config, params):
    endpoint = '/ranger/scans'
    filters_dict = {
        'name__icontains': params.get('name__icontains'),
        'site_id__exact': params.get('site_id__exact'),
        'sort': params.get('sort')
    }
    filters_dict = {k: v for k, v in filters_dict.items() if v is not None and v != '' and v != {} and v != []}
    params['filters'] = filters_dict
    return fetch_data_from_server(config, params, endpoint)


def get_queries(config, params):
    endpoint = '/ranger/queries'
    filters_dict = {
        'name__icontains': params.get('name__icontains'),
        'site_id__exact': params.get('site_id__exact'),
        'sort': params.get('sort')
    }
    filters_dict = {k: v for k, v in filters_dict.items() if v is not None and v != '' and v != {} and v != []}
    params['filters'] = filters_dict
    return fetch_data_from_server(config, params, endpoint)


def get_insights(config, params):
    endpoint = '/ranger/insights_summary'
    filters_dict = {
        'ghost__exact': params.get('ghost__exact'),
        'site_id__exact': params.get('site_id__exact'),
        'special_hint__exact': params.get('special_hint__exact'),
        'insight_status__exact': params.get('insight_status__exact'),
        'sort': params.get('sort')
    }
    filters_dict = {k: v for k, v in filters_dict.items() if v is not None and v != '' and v != {} and v != []}
    params['filters'] = filters_dict
    return fetch_data_from_server(config, params, endpoint)


def get_events(config, params):
    endpoint = '/ranger/events'
    filters_dict = {
        'site_id': params.get('site_id'),
        'id__exact': params.get('id__exact'),
        'alert_id__exact': params.get('alert_id__exact'),
        'timestamp__exact': params.get('timestamp__exact'),
        'description__contains': params.get('description__contains'),
        'description__icontains': params.get('description__icontains'),
        'type__exact': TYPE_DICT.get(params.get('type__exact')),
        'status__exact': EVENT_STATUS.get(params.get('status__exact')),
        'sort': params.get('sort')
    }
    filters_dict = {k: v for k, v in filters_dict.items() if v is not None and v != '' and v != {} and v != []}
    params['filters'] = filters_dict
    return fetch_data_from_server(config, params, endpoint)


def check_health(config):
    try:
        claroty_obj = Claroty(config)
        res = claroty_obj.generate_token()
        if res:
            return True
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(err)


operations = {
    'get_assets': get_assets,
    'get_asset_details': get_asset_details,
    'get_alerts': get_alerts,
    'get_alert_details': get_alert_details,
    'get_tasks': get_tasks,   #no data available and not found in UI
    'get_queries': get_queries,  # no data available
    'get_insights': get_insights,
    'get_events': get_events
}
