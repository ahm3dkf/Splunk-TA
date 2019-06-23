import urlparse
import json
from datetime import datetime, timedelta
from collections import namedtuple
from splunksdc import logging
from splunk_ta_o365.common.token import O365TokenProvider, O365Token
from splunk_ta_o365.common.utils import string_to_timestamp


logger = logging.get_module_logger()

_EPOCH = datetime(1970, 1, 1)


class O365PortalError(Exception):
    def __init__(self, response):
        payload = response.content
        message = str(response.status_code) + ':' + payload
        super(O365PortalError, self).__init__(message)
        self._code = None
        try:
            data = json.loads(payload)
            self._code = data['error']['code']
        except (KeyError, ValueError):
            # in case server response an invalid json.
            logger.exception('failed to get error code', body=payload)

    def should_retry(self):
        # Never retry if content was already expired.
        # Refer: https://msdn.microsoft.com/en-us/office-365/office-365-management-activity-api-reference
        return self._code != 'AF20051'


class O365PortalRegistry(object):
    @classmethod
    def load(cls, config):
        builders = {
            'Login': O365LoginPortal,
            'Management': O365ManagementPortal,
        }
        content = config.load('splunk_ta_o365_endpoints')
        lookup = dict()
        for realm, endpoints in content.items():
            lookup[realm] = {
                name: url for name, url in endpoints.items()
                if name in builders
            }
        return cls(lookup, builders)

    def __init__(self, lookup, builders):
        self._lookup = lookup
        self._builders = builders

    def __call__(self, name, tenant_id, realm):
        endpoints = self._lookup.get(realm)
        if not endpoints:
            raise ValueError('{} realm not found'.format(realm))
        builder = self._builders.get(name)
        if not builder:
            raise ValueError('Unknown portal class: {}'.format(name))
        endpoint = endpoints.get(name)
        if not endpoint:
            raise ValueError('{} endpoint for found'.format(name))
        if isinstance(endpoint, unicode):
            endpoint = endpoint.encode()
        return builder(tenant_id, endpoint)


class O365Portal(object):
    def __init__(self, tenant_id, endpoint):
        self._tenant_id = tenant_id
        self._endpoint = endpoint


class O365LoginPortal(O365Portal):
    def __init__(self, tenant_id, endpoint):
        super(O365LoginPortal, self).__init__(tenant_id, endpoint)
        path = '/{}/oauth2/token'.format(self._tenant_id)
        self._url = urlparse.urljoin(self._endpoint, path)

    def get_token_by_psk(self, client_id, client_secret, resource, session):
        response = session.post(self._url, data={
            'grant_type': 'client_credentials',
            'client_id': client_id,
            'client_secret': client_secret,
            'resource': resource
        })
        if response.status_code != 200:
            raise O365PortalError(response)
        content = response.json()
        token = O365Token(**content)
        logger.info('Acquire access token success.', expires_on=token.expires_on)
        return token


class O365ManagementPortal(O365Portal):
    def create_token_provider(self, policy):
        return O365TokenProvider(self._endpoint, policy)

    def create_subscription(self, content_type, request_timeout=60):
        return O365Subscription(self._tenant_id, self._endpoint, content_type, request_timeout)

    def create_service_comms(self):
        return O365ServiceCommunications(self._tenant_id, self._endpoint)


O365SubscriptionContent = namedtuple('O365SubscriptionContent', ['uri', 'id', 'expiration'])


class O365Subscription(O365Portal):
    def __init__(self, tenant_id, endpoint, content_type, request_timeout=60):
        super(O365Subscription, self).__init__(tenant_id, endpoint)
        path = '/api/v1.0/{}/activity/feed'.format(self._tenant_id)
        self._api = urlparse.urljoin(self._endpoint, path)
        self._content_type = content_type
        self._request_timeout = request_timeout

    def _list_available_content(self, session, start_time=None, end_time=None):
        params = {'contentType': self._content_type}
        if start_time and end_time:
            params.update({
                'startTime': self._time_to_string(start_time),
                'endTime': self._time_to_string(end_time)
            })
        return self._perform(session, 'GET', '/subscriptions/content', params)

    def list_available_content(self, session, start_time, end_time):
        for _start_time, _end_time in self._normalize_time_range(start_time, end_time):
            items = list()
            response = self._list_available_content(session, _start_time, _end_time)
            while True:
                array = response.json()
                items.extend(array)
                next_page_url = response.headers.get('NextPageUri')
                if not next_page_url:
                    break
                response = self._request(session, 'GET', next_page_url)
            yield [self._make_content(item) for item in items]

    def is_enabled(self, session):
        response = self._perform(session, 'GET', '/subscriptions/list')
        content = response.json()
        for item in content:
            if self._stricmp(item['contentType'], self._content_type):
                return self._stricmp(item['status'], 'enabled')
        return False

    def start(self, session):
        params = {'contentType': self._content_type}
        response = self._perform(session, 'POST', '/subscriptions/start', params)
        content = response.json()
        return self._stricmp(content['status'], 'enabled')

    def retrieve_content_blob(self, session, url):
        return self._request(session, 'GET', url)

    def _perform(self, session, method, operation, kwargs=None):
        url = self._api + operation
        return self._request(session, method, url, kwargs)

    def _request(self, session, method, url, kwargs=None):
        params = {
            'PublisherIdentifier': self._tenant_id
        }
        if kwargs:
            params.update(kwargs)
        logger.debug('Calling management activity API.', url=url, params=params, timeout=self._request_timeout)
        response = session.request(method, url, params=params, timeout=self._request_timeout)
        status_code = response.status_code
        if status_code != 200 and status_code != 201:
            raise O365PortalError(response)
        return response

    @staticmethod
    def _time_to_string(dt):
        return dt.strftime('%Y-%m-%dT%H:%M:%S')

    @staticmethod
    def _normalize_time_range(start_time, end_time):
        ranges = list()
        delta = timedelta(hours=1)
        while end_time - start_time > delta:
            _end_time = start_time + delta
            ranges.append((start_time, _end_time))
            start_time = _end_time
        ranges.append((start_time, end_time))
        ranges.reverse()
        return ranges

    @classmethod
    def _make_content(cls, data):
        expiration = string_to_timestamp(data['contentExpiration'])
        return O365SubscriptionContent(
            uri=data['contentUri'],
            id=data['contentId'],
            expiration=expiration
        )

    @staticmethod
    def _stricmp(s1, s2):
        return s1.lower() == s2.lower()


O365ServiceStatus = namedtuple('O365ServiceStatus', ['id', 'status_time', 'data'])
O365ServiceMessage = namedtuple('O365ServerMessage', ['id', 'last_updated_time', 'data'])


class O365ServiceCommunications(O365Portal):
    def __init__(self, tenant_id, endpoint):
        super(O365ServiceCommunications, self).__init__(tenant_id, endpoint)
        path = '/api/v1.0/{}/ServiceComms/'.format(self._tenant_id)
        self._api = urlparse.urljoin(self._endpoint, path)

    @classmethod
    def _make_service_status(cls, data):
        status_time = string_to_timestamp(data['StatusTime'])
        return O365ServiceStatus(
            id=data['Id'],
            status_time=status_time,
            data=json.dumps(data, sort_keys=True),
        )

    @classmethod
    def _make_service_message(cls, data):
        last_updated_time = string_to_timestamp(data['LastUpdatedTime'])
        return O365ServiceMessage(
            id=data['Id'],
            last_updated_time=last_updated_time,
            data=json.dumps(data, sort_keys=True)
        )

    def _make_url(self, operation):
        return self._api + operation

    def historical_status(self):
        return O365ServiceCommsOperation(
            self._make_url('HistoricalStatus'),
            self._make_service_status
        )

    def current_status(self):
        return O365ServiceCommsOperation(
            self._make_url('CurrentStatus'),
            self._make_service_status
        )

    def messages(self, last_updated_time):
        _filter = 'LastUpdatedTime ge {:%Y-%m-%dT%H:%M:%SZ}'.format(last_updated_time)
        return O365ServiceCommsOperation(
            self._make_url('Messages'),
            self._make_service_message,
            {'$filter': _filter}
        )


class O365ServiceCommsOperation(object):
    def __init__(self, url, factory, params=None):
        self._url = url
        self._params = params
        self._factory = factory

    def get(self, session):
        url = self._url
        params = self._params
        logger.debug('Calling service communication API.', url=url, params=params)
        response = session.get(url, params=params)
        if response.status_code != 200:
            raise O365PortalError(response)
        payload = response.json()
        items = payload.get('value', [])
        return [self._factory(item) for item in items]

    @property
    def source(self):
        return self._url




