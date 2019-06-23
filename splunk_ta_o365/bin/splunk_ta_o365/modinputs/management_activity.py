import time
import json
from datetime import datetime, timedelta
from splunksdc import logging
from splunksdc.utils import LogExceptions, LogWith
from splunksdc.config import StanzaParser, StringField, IntegerField
from splunksdc.collector import SimpleCollectorV1
from splunksdc.checkpoint import Partition
from splunksdc.batch import BatchExecutor, BatchExecutorExit
from splunk_ta_o365.common.portal import O365PortalRegistry, O365PortalError
from splunk_ta_o365.common.tenant import O365Tenant
from splunk_ta_o365.common.settings import Proxy, Logging


logger = logging.get_module_logger()


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
            StringField('sourcetype', default='o365:management:activity')
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

    def _create_subscription(self, mgmt):
        parser = StanzaParser([
            StringField('content_type'),
            IntegerField('request_timeout', lower=10, upper=600, default=60)
        ])
        args = self._extract_arguments(parser)
        return mgmt.create_subscription(args.content_type, args.request_timeout)

    def _create_executor(self):
        parser = StanzaParser([
            IntegerField('number_of_threads', lower=4, upper=64, default=16),
        ])
        args = self._extract_arguments(parser)
        return BatchExecutor(number_of_threads=args.number_of_threads)

    def _create_token_refresh_window(self):
        parser = StanzaParser([
            IntegerField('token_refresh_window', lower=400, upper=3600, default=600),
        ])
        args = self._extract_arguments(parser)
        return args.token_refresh_window

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
        subscription = self._create_subscription(mgmt)
        event_writer = self._create_event_writer(app)
        executor = self._create_executor()
        token_refresh_window = self._create_token_refresh_window()
        with app.open_checkpoint(self.name) as checkpoint:
            checkpoint.sweep()
            adapter = Adapter(app, proxy, token, subscription, checkpoint, event_writer, token_refresh_window)
            executor.run(adapter)
        return 0


class Adapter(object):
    def __init__(self, app, proxy, token, subscription, checkpoint, event_writer, token_refresh_window):
        self._app = app
        self._proxy = proxy
        self._token = token
        self._subscription = subscription
        self._checkpoint = Partition(checkpoint, '/v1/')
        self._event_writer = event_writer
        self._now = time.time
        self._token_refresh_window = token_refresh_window

    def is_aborted(self):
        return self._app.is_aborted()

    def discover(self):
        subscription = self._subscription
        token = self._token
        session = self._proxy.create_requests_session()

        self._token.auth(session)
        if not subscription.is_enabled(session):
            subscription.start(session)

        # This will change the time in previous hour and add 2 hours in it
        # For e.g. if current time is 3:20, this code will change it to 5:00
        end_time_epoch = self._now() // 3600 * 3600 + (2 * 3600)
        end_time = datetime.utcfromtimestamp(end_time_epoch)
        start_time = end_time - timedelta(days=7)

        logger.info('Start listing available content.')
        for page in subscription.list_available_content(session, start_time, end_time):
            if token.need_retire(self._token_refresh_window):
                logger.info('Access token will expire soon.')
                token.auth(session)
            content = [item for item in page if not self._has_ingested(item)]
            if not content:
                logger.debug('All content in this page have been ingested.')
                continue
            first, last = content[0], content[-1]
            logger.info('Fresh content found.', first=first.id, last=last.id)
            yield content

        self._clear_expired_markers()

    def do(self, content, session):
        try:
            session = self._token.set_auth_header(session)
            response = self._subscription.retrieve_content_blob(session, content.uri)
            # Removes duplicate events based on the Id
            unique_events = {item['Id']: item for item in response.json()}.values()
            return unique_events
        except Exception as e:
            exc_info = False if isinstance(e, O365PortalError) else True
            logger.error('Failed to retrieve content blob.', content_id=content.id, exc_info=exc_info)
            return e

    def done(self, content, result):
        if not isinstance(result, Exception):
            self._ingest_content_blob(content, result)

        if isinstance(result, O365PortalError):
            if not result.should_retry():
                logger.warning('Content is not available.', content_id=content.id)
                self._set_ingested_marker(content)

    def allocate(self):
        session = self._proxy.create_requests_session()
        return session

    def _has_ingested(self, content):
        checkpoint = self._checkpoint
        if not checkpoint.find(content.id):
            return False
        return True

    def _ingest_content_blob(self, content, events):
        data = '\n'.join([json.dumps(event, sort_keys=True) for event in events])
        self._event_writer.write_fileobj(data, source=content.uri)
        self._set_ingested_marker(content)
        logger.info('Ingesting content success.', content_id=content.id, count=len(events), size=len(data))

    def _set_ingested_marker(self, content):
        expiration = int(content.expiration + 60)
        self._checkpoint.set(content.id, expiration)

    def _clear_expired_markers(self):
        now = self._now()
        checkpoint = self._checkpoint
        expired = [
            key for key, expiration in checkpoint.items()
            if now > expiration
        ]
        for key in expired:
            checkpoint.delete(key)
        checkpoint.sweep()


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
        'content_type': {
            'title': 'Content Type',
            'description': 'What kind of Management Activity will be ingested.'
        },
        'number_of_threads': {
            'title': 'Number of Threads',
            'description': 'The number of threads used to download content blob in parallel.',
            'required_on_edit': False,
            'required_on_create': False
        },
        'token_refresh_window': {
            'title': 'Token Refresh Window',
            'description': "The number of seconds before the token's expiration time when the token should be refreshed.",
            'required_on_edit': False,
            'required_on_create': False
        },
        'request_timeout': {
            'title': 'Request Timeout',
            'description': "The number of seconds to wait before timeout while getting response from the subscription api.",
            'required_on_edit': False,
            'required_on_create': False
        }
    }

    SimpleCollectorV1.main(
        modular_input_run,
        title='Splunk Add-on for Microsoft Office 365 Management Activity',
        description='Ingest audit events from Office 365 Management Activity API',
        use_single_instance=False,
        arguments=arguments,
    )


