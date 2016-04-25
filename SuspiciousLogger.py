#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2013 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Command-line skeleton application for Admin Reports API.
Usage:
  $ python sample.py

You can also get help on all the command-line flags the program understands
by running:

  $ python sample.py --help

"""

import argparse
import codecs
import httplib2
import logging
import os
import pygeoip
import sys
import time

from copy import copy
from datetime import datetime
from IPy import IP
from googleapiclient import discovery, errors
from oauth2client import file as oauth_file
from oauth2client import client, tools
from pygeoip.const import ENCODING as GEOIP_ENC
from threading import Thread, Lock, active_count as active_thread_count

RFC3339_ZULU_FMT = '%Y-%m-%dT%H:%M:%S.%fZ'
DIR_NAME = os.path.dirname(__file__)
# CLIENT_SECRETS is name of a file containing the OAuth 2.0 information
# <https://cloud.google.com/console#/project/803928506099/apiui>
CLIENT_SECRETS = os.path.join(DIR_NAME, 'client_secrets.json')
SESSION_STATE = os.path.join(DIR_NAME, 'SuspiciousLogger.dat')
GEOIP_DATA = os.path.join(DIR_NAME, 'GeoIP_data', 'GeoLiteCity.dat')
GEOIP = pygeoip.GeoIP(GEOIP_DATA, pygeoip.MMAP_CACHE)


def oauthorize(client_secrets, session_file):
    """Takes a path to a client_secrets.json and a session.dat file,
    performs an OAuth auth-flow and returns a service object."""
    # If the credentials don't exist or are invalid run through the native
    # client flow. The Storage object will ensure that if successful the good
    # credentials will get written back to the file.
    storage = oauth_file.Storage(session_file)
    credentials = storage.get()

    if credentials is None or credentials.invalid:
        # Prevent obnoxious browser window launching if our session is expired
        faux_parser = argparse.ArgumentParser(parents=[tools.argparser])
        flow_flags = faux_parser.parse_args("--noauth_local_webserver".split())
        scope = [
            'https://www.googleapis.com/auth/admin.reports.audit.readonly',
            'https://www.googleapis.com/auth/admin.reports.usage.readonly'
        ]
        err_msg = tools.message_if_missing(client_secrets)
        flow = client.flow_from_clientsecrets(client_secrets, scope=scope,
                                              message=err_msg)
        credentials = tools.run_flow(flow, storage, flow_flags)

    # Create an httplib2.Http object to handle our HTTP requests and do auth
    http = httplib2.Http()
    http = credentials.authorize(http)

    return discovery.build('admin', 'reports_v1', http=http)


def filter_collection(collection, collection_filter):
    """Tries to execute a query -- collection_filter -- against a collection
    returning the result on success and the empty dict on failure."""
    try:
        req = collection.list(**collection_filter)
        # API access happens here
        return req.execute()
    except client.AccessTokenRefreshError:
        logging.critical("Authorization has expired, re-authing next run.")
        return {}
    except errors.HttpError as err:
        logging.error(
            "Collection of userKey=%s, actorIpAddress=%s, failed: %s",
            collection_filter['userKey'],
            collection_filter['actorIpAddress'],
            err)
        return {}


def fmt_response(response):
    """Provides basic formatting for some common collection.list fields."""
    log_fmt = "{time} {ip} {loc} {actor} {event} "
    if 'login_type' in response:
        log_fmt += response['login_type']
    return log_fmt.format(**response)


def geoip_metro(ip_addr):
    """Transform an IP into a reasonably readable country and region code,
    preferring metro_code over region_code (metro code seems to be what is
    most comprehensible, when available)."""
    location = GEOIP.record_by_addr(ip_addr)
    if location:
        metro = location.get('metro_code', 'Unknown')
        country = location.get('country_code3', 'Unknown')
        if not metro:
            # fall back to this if there's no metro_code
            metro = "{}, {}".format(location.get('city', 'Unknown'),
                                    location.get('region_code', 'Unknown'))
    else:
        # location is None
        metro = 'Unknown'
        country = 'Unknown'
    return "{}, {}".format(metro, country)


def repack_collection(col):
    """Repacks a collection.list item into a dictionary with the record keyed
    off it's globally unique etag, ensuring merged collections are not
    redundant while also flatting them quite a bit for greater ease in sorting
    and formatting."""
    packed = {}
    for entry in col:
        etag = entry['etag']

        packed[etag] = {'actor': entry['actor']['email'],
                        'ip':    entry['ipAddress'],
                        'loc':   geoip_metro(entry['ipAddress']),
                        'time':  datetime.strptime(entry['id']['time'],
                                                    RFC3339_ZULU_FMT)}
        for event in entry['events']:
            if 'name' in event:
                packed[etag]['event'] = event['name']
            if 'parameters' in event:
                for params in event['parameters']:
                    if 'name' and 'value' in params:
                        packed[etag][params['name']] = params['value']
        logging.debug("Repacked entry as: %s", packed[etag])
    return packed


def valid_selector(selector):
    """Validator for the 'selector' arg type -- checks for one or more email
    addresses (possibly comma separated) or IP addresses or CIDR masks.
    Returns an IP object, or a list of email addresses. The result is always
    iterable.

    Validation on email here need not be tight, just type it right."""
    results = []

    for selector in selector.split(','):
        if selector == 'all':
            # Return early in this case as additional selectors are redundant
            return [selector]
        elif '@' in selector:
            # it's probably email address(es)
            results.append(selector)
        else:
            try:
                # iterate the IP iterable now, in case we're building a
                # heterogenous list of selector types
                results.extend([ip for ip in IP(selector)])
            except:
                raise argparse.ArgumentTypeError(
                    "'{}' is not an IP or email.".format(selector))
    return results


def set_collection_filter(collection_filter, selector):
    """Set up the collection filter based on the type of the selector."""
    # set these selectors to defaults
    collection_filter['userKey'] = 'all'
    collection_filter['actorIpAddress'] = None

    if isinstance(selector, IP):
        collection_filter['actorIpAddress'] = selector
    else:
        collection_filter['userKey'] = selector

    return collection_filter


def query_worker(collection_filter, selector, responses):
    """A worker fn for authorizing then querying against the reports API.

    The SSL connection created in oauthorize() is subsequently used by the
    query so 'service' and 'collection' need to be local to each thread."""
    # Construct the service object for the Admin Reports API.
    service = oauthorize(CLIENT_SECRETS, SESSION_STATE)
    # Select the activities collection
    collection = service.activities()
    collection_filter = set_collection_filter(collection_filter, selector)
    response = filter_collection(collection, collection_filter)

    if 'items' in response:
        final_collection = repack_collection(response['items'])
        update_lock = Lock()
        with update_lock:
            responses.update(final_collection)
    else:
        logging.info("Did not find results for %s, %s",
                     selector, collection_filter)


def spawn_workers(jobs, selectors, collection_filter, responses):
    """Spawn a pool of workers using taking selectors, collection_filter and
    responses dicts and constrained to a maximum number of jobs."""
    logging.info("Spawning %s threads", min(jobs, len(selectors)))
    while len(selectors) is not 0:
        if active_thread_count() < jobs:
            selector = selectors.pop()
            worker = Thread(target=query_worker, name=selector,
                            args=(collection_filter, selector, responses))
            worker.start()


def manage_workers(flags, collection_filter, responses):
    """Monitor a response dict printing new entries and spawning new workers as
    needed."""
    old_responses, login_sequence = {}, []
    while True:
        if active_thread_count() is 1:
            if list(responses.keys()) != list(old_responses.keys()):
                logging.critical("New entries found.")
                old_sequence = login_sequence
                login_sequence = sorted(responses,
                                        key=lambda x: responses[x]['time'])
                print(("\n".join([fmt_response(responses[k])
                                  for k in login_sequence
                                  if k not in old_sequence])))
            else:
                logging.info("No new entries.")

            if flags.follow:
                logging.info("Sleeping for %s seconds.", flags.interval)
                time.sleep(flags.interval)
                old_responses = responses
                selectors = copy(flags.selectors)
                spawn_workers(flags.jobs, selectors,
                              collection_filter, responses)
            else:
                return


def main(argv):
    """This tool composes the rudiments of exposing the various aspect of the
    admin-sdk reports API:
    https://developers.google.com/admin-sdk/reports/v1/reference/activities/list
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interval', default=120, type=int)
    parser.add_argument('-j', '--jobs', nargs=1, default=25,
                        help="Maximum number of query threads to spawn.")
    parser.add_argument('-v', '--verbose', dest='verbosity',
                        action='count',
                        default=0,
                        help='One invocation: INFO level, two: DEBUG.')
    parser.add_argument('-f', '--follow', action='store_true', default=False)
    parser.add_argument('selectors', type=valid_selector,
                        help='An IP, CIDR range, gmail address, comma separated\
                        list of all three or the word "all".')

    subparsers = parser.add_subparsers(help='List all events or filter by \
                                       eventname and additional filters.')
    subparsers.add_parser('list', help='List all events.')

    event_parser = subparsers.add_parser('events',
                                         help='Filter log lines by event type \
                                         and additional filters.')
    event_parser.add_argument('eventName')
    event_parser.add_argument('--filters')

    # Parse the command-line flags.
    flags = parser.parse_args(argv[1:])

    # Transform -v's to an number between 10 and logging.WARNING (==30)
    loglevel = max(logging.WARNING - (flags.verbosity * 10), 10)
    logging.basicConfig(level=loglevel)
    logging.info("Log level set to: '%s'", logging.getLevelName(loglevel))

    # Set up the base collection filter
    collection_filter = {'applicationName': 'login'}

    # Provided flags has this attr, filters will at least be None
    if hasattr(flags, 'eventName'):
        collection_filter['eventName'] = flags.eventName
        collection_filter['filters'] = flags.filters

    # responses dict has new results .merge()'d within a lock by each thread
    responses, login_sequence = {}, []
    selectors = copy(flags.selectors)
    spawn_workers(flags.jobs, selectors, collection_filter, responses)

    try:
        manage_workers(flags, collection_filter, responses)
    except KeyboardInterrupt:
        logging.critical('Exitting early on user request.')
        sys.exit(127)
    else:
        sys.exit(0)

if __name__ == '__main__':
    main(sys.argv)
