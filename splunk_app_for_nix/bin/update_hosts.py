import csv
import logging
import os
import sys

import splunk.appserver.mrsparkle.lib.util as app_util
import splunk.search


def getOrder(keys, csvHeaders):
    order = []
    for key in keys:
        for i, header in enumerate(csvHeaders):
            if key == header.strip():
                order.append(i)

    return order


def get_hosts_in_lookup_file(file):
    with open(file, 'rb') as csvfile:
        reader = csv.reader(csvfile)
        csvdata = [row for row in reader]
    order = getOrder(['unix_category', 'unix_group', 'host'], csvdata[0])
    old_hosts = dict()
    for row in csvdata[1:]:
        if len(row) == 3:
            old_hosts[row[order[2]]] = [row[order[0]], row[order[1]]]
    return old_hosts


def get_hosts():
    token = sys.stdin.readlines()[0]
    token = token.strip()
    job = splunk.search.dispatch('| metadata type=hosts `metadata_index`',
                                 namespace='splunk_app_for_nix',
                                 earliestTime='-7d', sessionKey=token)
    splunk.search.waitForJob(job)
    return [unicode(item['host']) for item in job.results]


def setup_logger():
    LOG_FILENAME = os.path.join(os.environ.get('SPLUNK_HOME'), 'var', 'log',
                                'splunk', 'unix_installer.log')
    logger = logging.getLogger('unix_installer')
    logger.setLevel(logging.DEBUG)
    handler = logging.handlers.RotatingFileHandler(LOG_FILENAME,
                                                   maxBytes=1024000,
                                                   backupCount=5)
    handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    handler.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    return logger


if __name__ == '__main__':

    logger = setup_logger()
    logger.info('Started updating hosts lookup file for app-unix')
    lookup_csv = os.path.join(app_util.get_apps_dir(), 'splunk_app_for_nix', 'lookups',
                              'dropdowns.csv')

    filtered_csv_data = []

    if os.path.isfile(lookup_csv):
        hosts = get_hosts()
        old_hosts = get_hosts_in_lookup_file(lookup_csv)
        for host in hosts:
            if host in old_hosts:
                category = old_hosts[host][0]
                group = old_hosts[host][1]
                filtered_csv_data.append([category, group, host])
        logger.info(
            'Keeping %d items in the old host lookup file. '
            'Removing %d hosts that are inactive for the last 7 days' %
            (len(filtered_csv_data),
             len(old_hosts) - len(filtered_csv_data) - 2))

    else:
        logger.info(
            'No existing csv found, creating empty'
            ' csv with default category and group')

    filtered_csv_data.insert(0, ['all_hosts', 'default', '*'])
    filtered_csv_data.insert(0, ['unix_category', 'unix_group', 'host'])

    with open(lookup_csv, 'wb') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerows(filtered_csv_data)

    logger.info('Finished updating hosts lookup file for app-unix')
