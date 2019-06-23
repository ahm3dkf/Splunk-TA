import urllib2
import requests
from splunksdc import logging
from splunksdc.config import StanzaParser, StringField, BooleanField, LogLevelField
from splunk_ta_o365 import set_log_level


logger = logging.get_module_logger()


class Proxy(object):
    @staticmethod
    def _wipe(settings):
        params = vars(settings).copy()
        del params['password']
        return params

    @classmethod
    def load(cls, config):
        content = config.load('splunk_ta_o365/settings', stanza='proxy', virtual=True)
        parser = StanzaParser([
            BooleanField('disabled', reverse=True, rename='enabled'),
            StringField('host'),
            StringField('port'),
            StringField('username'),
            StringField('password')
        ])
        settings = parser.parse(content)
        logger.info('Load proxy settings success.', **cls._wipe(settings))
        return cls(settings)

    def __init__(self, settings):
        self._settings = settings

    def _make_url(self, scheme):
        settings = self._settings
        endpoint = '{host}:{port}'.format(
            host=settings.host,
            port=settings.port
        )
        auth = None
        if settings.username and len(settings.username) > 0:
            auth = urllib2.quote(settings.username.encode(), safe='')
            if settings.password and len(settings.password) > 0:
                auth += ':'
                auth += urllib2.quote(settings.password.encode(), safe='')

        if auth:
            endpoint = auth + '@' + endpoint

        url = scheme + '://' + endpoint
        return url

    def create_requests_session(self):
        session = requests.Session()
        if self._settings.enabled:
            server_uri = self._make_url('http')
            session.proxies.update({'http': server_uri, 'https': server_uri})
        return session


class Logging(object):
    @classmethod
    def load(cls, config):
        content = config.load('splunk_ta_o365_settings', stanza='logging')
        parser = StanzaParser([
            LogLevelField('log_level', default='WARNING')
        ])
        settings = parser.parse(content)
        return cls(settings)

    def __init__(self, settings):
        self._settings = settings

    def apply(self):
        set_log_level(self._settings.log_level)

