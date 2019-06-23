
from splunksdc.config import StanzaParser, StringField
from splunk_ta_o365.common.token import O365TokenPSKPolicy


class O365Tenant(object):
    @classmethod
    def create(cls,  config, tenant_name):
        content = config.load('splunk_ta_o365/tenants', tenant_name, virtual=True)
        parser = StanzaParser([
            StringField('endpoint'),
            StringField('tenant_id'),
            StringField('client_id'),
            StringField('client_secret')
        ])
        profile = parser.parse(content)
        return O365Tenant(**vars(profile))

    def __init__(self, endpoint, tenant_id, client_id, client_secret):
        self._realm = endpoint
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret

    def create_management_portal(self, registry):
        return registry('Management', self._tenant_id, self._realm)

    def create_token_policy(self, registry):
        login = registry('Login', self._tenant_id, self._realm)
        return O365TokenPSKPolicy(login, self._client_id, self._client_secret)
