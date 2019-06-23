import time


class O365Token(object):
    def __init__(self, token_type, access_token, expires_on, **kwargs):
        self._token_type = token_type
        self._access_token = access_token
        self._expires_on = int(expires_on)
        self._now = time.time

    def ttl(self):
        return self._expires_on - self._now()

    def need_retire(self, min_ttl):
        return self.ttl() < min_ttl

    @property
    def token_type(self):
        return self._token_type

    @property
    def access_token(self):
        return self._access_token

    @property
    def expires_on(self):
        return self._expires_on


class O365TokenPSKPolicy(object):
    def __init__(self, portal, client_id, client_secret):
        self._portal = portal
        self._client_id = client_id
        self._client_secret = client_secret

    def __call__(self, resource, session):
        return self._portal.get_token_by_psk(self._client_id, self._client_secret, resource, session)


class O365TokenProvider(object):
    def __init__(self, resource, policy):
        self._resource = resource
        self._policy = policy
        self._token = None

    def set_auth_header(self, session):
        session.headers.update({
            'Authorization': '{} {}'.format(
                self._token.token_type,
                self._token.access_token
            )
        })
        return session

    def auth(self, session):
        self._token = self._policy(self._resource, session)
        return self.set_auth_header(session)

    def need_retire(self, min_ttl):
        if not self._token:
            return True
        return self._token.need_retire(min_ttl)
