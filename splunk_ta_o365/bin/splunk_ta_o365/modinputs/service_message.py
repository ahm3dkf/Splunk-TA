import time
from datetime import datetime, timedelta
from splunksdc import logging
from splunksdc.utils import LogExceptions, LogWith
from splunksdc.config import StanzaParser, StringField
from splunksdc.collector import SimpleCollectorV1
from splunksdc.checkpoint import Partition
from splunk_ta_o365.common.portal import O365PortalRegistry
from splunk_ta_o365.common.tenant import O365Tenant
from splunk_ta_o365.common.settings import Proxy, Logging


logger = logging.get_module_logger()


class ServiceMessageConsumer(object):
    def __init__(self, checkpoint, event_writer, portal, session):
        self._checkpoint = Partition(checkpoint, '/v1/')
        self._event_writer = event_writer
        self._portal = portal
        self._session = session
        self._now = time.time

    def run(self):
        now = self._now()
        last_updated_time = datetime.utcfromtimestamp(now) - timedelta(days=7)
        messages = self._portal.messages(last_updated_time)
        source = messages.source
        logger.info('Start retrieving messages.')
        for message in messages.get(self._session):
            if self._has_updated(message):
                self._ingest(message, source)
        self._clear_checkpoint()

    def _ingest(self, message, source):
        self._event_writer.write_event(message.data, message.last_updated_time, source=source)
        self._checkpoint.set(message.id, message.last_updated_time)

    def _has_updated(self, message):
        item = self._checkpoint.find(message.id)
        if not item:
            return True
        if item.value != message.last_updated_time:
            return True
        return False

    def _clear_checkpoint(self):
        now = self._now()
        checkpoint = self._checkpoint
        expired = [
            key for key, last_updated_time in checkpoint.items()
            if now - last_updated_time > 31104000
        ]
        for key in expired:
            checkpoint.delete(key)
        checkpoint.sweep()


class DataInput(object):
    def __init__(self, stanza):
        self._kind = stanza.kind
        self._name = stanza.name
        self._args = stanza.content
        self._start_time = int(time.time())

    def _create_metadata(self):
        stanza = self._kind + '://' + self._name
        parser = StanzaParser([
            StringField('index'),
            StringField('host'),
            StringField('stanza', fillempty=stanza),
            StringField('sourcetype', default='o365:service:message')
        ])
        return self._extract_arguments(parser)

    def _get_tenant_name(self):
        parser = StanzaParser([
            StringField('tenant_name'),
        ])
        args = self._extract_arguments(parser)
        return args.tenant_name

    def _create_tenant(self, config):
        tenant_name = self._get_tenant_name()
        return O365Tenant.create(config, tenant_name)

    def _create_event_writer(self, app):
        metadata = self._create_metadata()
        return app.create_event_writer(None, **vars(metadata))

    def _extract_arguments(self, parser):
        return parser.parse(self._args)

    @property
    def name(self):
        return self._name

    @property
    def start_time(self):
        return self._start_time

    @LogWith(datainput=name, start_time=start_time)
    @LogExceptions(logger, 'Data input was interrupted by an unhandled exception.', lambda e: -1)
    def run(self, app, config):
        Logging.load(config).apply()
        proxy = Proxy.load(config)
        registry = O365PortalRegistry.load(config)
        tenant = self._create_tenant(config)
        mgmt = tenant.create_management_portal(registry)
        policy = tenant.create_token_policy(registry)
        token = mgmt.create_token_provider(policy)
        portal = mgmt.create_service_comms()
        session = proxy.create_requests_session()
        session = token.auth(session)
        event_writer = self._create_event_writer(app)
        with app.open_checkpoint(self.name) as checkpoint:
            checkpoint.sweep()
            consumer = ServiceMessageConsumer(checkpoint, event_writer, portal, session)
            return consumer.run()


def modular_input_run(app, config):
    array = app.inputs()
    di = DataInput(array[0])
    return di.run(app, config)


def main():
    arguments = {
        'tenant_name': {
            'title': 'Tenant Name',
            'description': 'Which Office 365 tenant will be used.'
        },
    }

    SimpleCollectorV1.main(
        modular_input_run,
        title='Splunk Add-on for Microsoft Office 365 Service Message',
        description='Ingest service messages from Office 365 Service Communications API',
        use_single_instance=False,
        arguments=arguments,
    )


