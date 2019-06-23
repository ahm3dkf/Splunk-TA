import os
import os.path
import base64
import re
import json
import requests
import logging
import urllib
import urllib2
import urlparse
from urlparse import urljoin


logger = logging.getLogger('splunk_ta_o365_rest_handlers')


class RestError(Exception):
    def __init__(self, method, endpoint, response):
        trace = response.content
        try:
            trace = json.loads(trace)
        finally:
            pass
        status_code = response.status_code
        message = '{}:{} {}'.format(status_code, method, endpoint)
        super(RestError, self).__init__(message)
        self._trace = trace

    @property
    def trace(self):
        return self._trace


class RestCTX(object):
    def __init__(self, uri, token, appname, session):
        self._uri = uri
        self._token = token
        self._appname = appname
        self._user = 'nobody'
        self._session = session

    @classmethod
    def _make_config_path(cls, filename, stanza):
        endpoint = '/configs/conf-{filename}'.format(filename=filename)
        if stanza:
            endpoint += '/' + urllib.quote(stanza, '')
        return endpoint

    def load_config(self, filename, stanza=None):
        endpoint = self._make_config_path(filename, stanza)
        return self._get(endpoint)

    def create_stanza(self, filename, name, fields):
        endpoint = self._make_config_path(filename, None)
        fields['name'] = name
        return self._post(endpoint, data=fields)

    def update_stanza(self, filename, name, fields):
        endpoint = self._make_config_path(filename, name)
        return self._post(endpoint, data=fields)

    def delete_stanza(self, filename, name):
        endpoint = self._make_config_path(filename, name)
        return self._delete(endpoint)

    def create_secret(self, name, secret):
        endpoint = '/storage/passwords'
        return self._post(endpoint, data={'name': name, 'password': secret})

    def update_secret(self, name, secret):
        endpoint = '/storage/passwords/{}'.format(name)
        return self._post(endpoint, data={'password': secret})

    def load_secret(self, name):
        endpoint = '/storage/passwords/{name}'.format(name=name)
        return self._get(endpoint)

    def delete_secret(self, name):
        endpoint = '/storage/passwords/{name}'.format(name=name)
        return self._delete(endpoint)

    def _assemble_uri(self, endpoint):
        path = '/servicesNS/{user}/{appname}'.format(
            user=self._user, appname=self._appname
        )
        path += endpoint
        return urljoin(self._uri, path)

    def get(self, endpoint):
        return self._get(endpoint)

    def _get(self, endpoint):
        return self._request('GET', endpoint)

    def _post(self, endpoint, **kwargs):
        return self._request('POST', endpoint, **kwargs)

    def _delete(self, endpoint):
        return self._request('DELETE', endpoint)

    def _request(self, method, endpoint, **kwargs):
        uri = self._assemble_uri(endpoint)
        kwargs['headers'] = {'Authorization': 'Splunk %s' % self._token}
        kwargs['params'] = {'output_mode': 'json', 'count': 0}
        kwargs['verify'] = False
        response = self._session.request(method, uri, **kwargs)
        return response


class RestHandler(object):
    def __init__(self, method, path, form, ctx):
        self._method = method
        self._path = path
        self._form = form
        self._ctx = ctx

    @staticmethod
    def _response(status, data=None):
        if not data:
            data = {'status': status, 'entry': []}
        payload = json.dumps(data)
        return {'status': status, 'payload': payload}

    @staticmethod
    def _error(status, text=None, trace=None):
        payload = json.dumps({
            'messages': [{
                'text': text, 'type': 'ERROR'
            }],
            'trace': trace
        })
        return {'status': status, 'payload': payload}

    @staticmethod
    def _forward(response):
        return {'status': response.status_code, 'payload': response.content}

    def process(self, kwargs):
        try:
            method = self._method
            method = method.lower()
            func = getattr(self, method, None)
            if not func:
                return self._error(405, 'Method Not Allowed')
            for key, value in kwargs.items():
                if value:
                    kwargs[key] = urllib.unquote(value)
            return func(**kwargs)
        except Exception as e:
            # the message property of some exceptions may not be a string.
            text = str(e.message)
            return self._error(500, text)


class DotConfHandler(RestHandler):
    def __init__(self, method, path, form, ctx, filename, secret_name, credentials):
        super(DotConfHandler, self).__init__(method, path, form, ctx)
        self._filename = filename
        self._secret_name = secret_name
        self._credentials = credentials

    def post(self, name):
        try:
            form = self._encrypt(self._form)
            if not name or name == '_new':
                return self._create_stanza(form)
            return self._update_stanza(name, form)
        except RestError as e:
            return self._error(500, e.message, e.trace)

    def get(self, name):
        response = self._ctx.load_config(self._filename, name)
        if response.status_code != 200:
            return self._forward(response)
        try:
            payload = response.json()
            payload['entry'] = self._decrypt(payload['entry'])
            return self._response(200, payload)
        except RestError as e:
            return self._error(500, e.message, e.trace)

    def delete(self, name):
        response = self._ctx.delete_stanza(self._filename, name)
        return self._forward(response)

    def _update_stanza(self, name, form):
        response = self._ctx.update_stanza(self._filename, name, form)
        return self._forward(response)

    def _create_stanza(self, form):
        name = form.pop('name')
        response = self._ctx.create_stanza(self._filename, name, form)
        return self._forward(response)

    def _load_secret(self):
        response = self._ctx.load_secret(self._secret_name)
        if response.status_code != 200:
            raise RestError('GET', self._secret_name, response)
        payload = response.json()
        item = payload['entry'][0]
        password = item['content']['clear_password']
        return password

    def _decrypt(self, entry):
        for item in entry:
            item['content'] = self._decode(item['content'])
        return entry

    def _encrypt(self, form):
        return self._encode(form)

    def _decode(self, fields):
        def _dec(value, secret):
            sign, payload = value[:3], value[3:]
            if sign != '$1$':
                return value
            if not payload:
                return value
            cipher = base64.b64decode(payload)
            return self._rc4(cipher, secret)
        return self._transform_credential_fields(fields, _dec)

    def _encode(self, fields):
        def _enc(value, secret):
            if not value:
                return value
            cipher = self._rc4(value, secret)
            return '$1$' + base64.b64encode(cipher)
        return self._transform_credential_fields(fields, _enc)

    def _transform_credential_fields(self, fields, func):
        if not self._credentials:
            return fields
        credentials = [key for key, value in fields.items() if key in self._credentials and value]
        if not credentials:
            return fields

        secret = self._load_secret()
        if not secret:
            return fields

        for key in credentials:
            value = fields[key]
            fields[key] = func(value, secret)
        return fields

    @classmethod
    def _rc4(cls, data, key):
        """RC4 encryption and decryption method."""
        S, j, out = list(range(256)), 0, []

        for i in range(256):
            j = (j + S[i] + ord(key[i % len(key)])) % 256
            S[i], S[j] = S[j], S[i]

        i = j = 0
        for ch in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            out.append(chr(ord(ch) ^ S[(S[i] + S[j]) % 256]))

        return "".join(out)


class DotConfHandlerFactory(object):
    def __init__(self, filename, secret=None, credentials=None):
        self._filename = filename
        self._secret = secret
        self._credentials = credentials

    def __call__(self, method, path, form, ctx):
        return DotConfHandler(
            method, path, form, ctx,
            self._filename, self._secret, self._credentials
        )


class NotFoundHandler(RestHandler):
    def process(self, kwargs):
        return self._error(404, 'Not Found')


class SecretHandler(RestHandler):
    _KEY = 'splunk_ta_o365_secret'

    def get(self):
        response = self._ctx.load_secret(self._KEY)
        return self._forward(response)

    def post(self):
        secret = self._form.get('password')
        override = self._form.get('override')
        if override:
            response = self._ctx.update_secret(self._KEY, secret)
        else:
            response = self._ctx.create_secret(self._KEY, secret)
        return self._forward(response)

    def delete(self):
        response = self._ctx.delete_secret(self._KEY)
        return self._forward(response)


class CheckpointHandler(RestHandler):
    _environ = os.environ
    _known_schema = [
        'splunk_ta_o365_management_activity',
        'splunk_ta_o365_service_status',
        'splunk_ta_o365_service_message',
    ]

    @classmethod
    def _isfile(cls, path):
        return os.path.isfile(path)

    @classmethod
    def _remove(cls, path):
        return os.remove(path)

    def delete(self, schema, name):
        if schema not in self._known_schema:
            return self._error(401, 'Unknown modular input type')
        if name.find('..') != -1:
            return self._error(401, 'Invalid data input name')
        path = self._make_ckpt_path(schema, name)
        if self._isfile(path):
            self._remove(path)
        return self._response(200)

    @classmethod
    def _make_ckpt_path(cls, schema, name):
        root = cls._environ.get('SPLUNK_HOME', '/opt/splunk')
        path = os.path.join(root, 'var', 'lib', 'splunk', 'modinputs', schema, name)
        path += '.ckpt'
        return path


class AuthHandlerFactory(object):
    def __init__(self, session):
        self._session = session

    def __call__(self, method, path, form, ctx):
        return AuthHandler(method, path, form, ctx, self._session)


class AuthHandler(RestHandler):
    def __init__(self, method, path, form, ctx, session):
        super(AuthHandler, self).__init__(method, path, form, ctx)
        self._session = session

    def post(self, name):
        try:
            tenant = self._load_existed_tenant(name) if name else dict()

            tenant.update(self._form)
            tenant_id = tenant.get('tenant_id')
            client_id = tenant.get('client_id')
            client_secret = tenant.get('client_secret')

            realm = tenant.get('endpoint')
            login, mgmt = self._load_endpoint(realm)
            if not login or not mgmt:
                return self._error(400, 'Invalid endpoint')

            proxy = self._load_proxy()
            return self._validate_credentials(proxy, login, mgmt, tenant_id, client_id, client_secret)
        except RestError as e:
            return self._error(500, e.message, e.trace)

    def _load_proxy(self):
        content = self._get_entity('/splunk_ta_o365/settings/proxy')
        enabled = not content.get('disabled', True)
        host = content.get('host', '')
        port = content.get('port', '')
        username = content.get('username', '')
        password = content.get('password', '')
        if not enabled or not host or not port:
            return None

        endpoint = '{host}:{port}'.format(host=host, port=port)
        auth = None
        if username and len(username) > 0:
            auth = urllib2.quote(username.encode(), safe='')
            if password and len(password) > 0:
                auth += ':'
                auth += urllib2.quote(password.encode(), safe='')

        if auth:
            endpoint = auth + '@' + endpoint

        url = 'http://' + endpoint
        return {'http': url, 'https': url}

    def _load_existed_tenant(self, name):
        endpoint = '/splunk_ta_o365/tenants/{}'.format(name)
        content = self._get_entity(endpoint)
        return content

    def _load_endpoint(self, realm):
        endpoint = '/configs/conf-splunk_ta_o365_endpoints/{stanza}'.format(stanza=realm)
        content = self._get_entity(endpoint)
        return content.get('Login'), content.get('Management')

    def _validate_credentials(self, proxy, login, mgmt, tenant_id, client_id, client_secret):
        url = urlparse.urljoin(login, '/{}/oauth2/token'.format(tenant_id))
        response = self._session.request('POST', url, data={
            'grant_type': 'client_credentials',
            'client_id': client_id,
            'client_secret': client_secret,
            'resource': mgmt
        }, proxies=proxy)
        if response.status_code != 200:
            trace = response.json()
            msg = trace.get('error_description')
            return self._error(400, msg, trace)
        return self._response(200)

    def _get_entity(self, endpoint):
        response = self._ctx.get(endpoint)
        if response.status_code != 200:
            raise RestError('GET', endpoint, response)
        entity = response.json()['entry'][0]
        return entity['content']


class RestRequest(object):
    def __init__(self, data):
        self._data = json.loads(data)

    @property
    def path(self):
        return self._data.get('path_info', '')

    @property
    def method(self):
        return self._data['method']

    @property
    def form(self):
        form = self._data.get('form')
        if not form:
            return {}
        return {item[0]: item[1] for item in form}

    @property
    def server_token(self):
        return self._data['session']['authtoken']

    @property
    def server_uri(self):
        return self._data['server']['rest_uri']


class RestApp(object):
    @classmethod
    def create(cls, routes, appname, session):
        app = cls(appname, session)
        for regex, handler_class in routes:
            app.add(regex, handler_class)
        return app

    def __init__(self, appname, session):
        self._routes = list()
        self._appname = appname
        self._session = session

    def add(self, regex, handler_factory):
        pattern = re.compile(regex)
        pair = pattern, handler_factory
        self._routes.append(pair)

    def _match(self, path):
        for pattern, handler_factory in self._routes:
            match = pattern.match(path)
            if match:
                kwargs = match.groupdict()
                return handler_factory, kwargs
        else:
            return NotFoundHandler, {}

    def dispatch(self, data):
        req = RestRequest(data)
        ctx = RestCTX(req.server_uri, req.server_token, self._appname, self._session)
        handler_factory, kwargs = self._match(req.path)
        handler = handler_factory(req.method, req.path, req.form, ctx)
        return handler.process(kwargs)


def create_rest_app(session):
    return RestApp.create([(
        r'auth(/(?P<name>.+))?',
        AuthHandlerFactory(session)
    ), (
        r'checkpoints/(?P<schema>.+)/(?P<name>.+)',
        CheckpointHandler
    ), (
        r'secret', SecretHandler
    ), (
        r'settings/(?P<name>proxy)',
        DotConfHandlerFactory(
            'splunk_ta_o365_settings',
            secret='splunk_ta_o365_secret',
            credentials=['password']
        )
    ), (
        r'tenants(/(?P<name>.+))?',
        DotConfHandlerFactory(
            'splunk_ta_o365_tenants',
            secret='splunk_ta_o365_secret',
            credentials=['client_secret']
        )
    )], 'splunk_ta_o365', session)


# Do not block unittest running without splunk python env.
try:
    from splunk.persistconn.application import PersistentServerConnectionApplication

    class O365RestApp(PersistentServerConnectionApplication):
        def __init__(self, *args, **kwargs):
            super(O365RestApp, self).__init__()
            self._app = create_rest_app(requests)

        def handle(self, data):
            # return {'status': 200, 'payload': data}
            return self._app.dispatch(data)

        def handleStream(self, handle, in_string):
            assert False

except ImportError:
    pass
