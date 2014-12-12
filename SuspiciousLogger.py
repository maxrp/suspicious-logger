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
import httplib2
import os
import pygeoip
import sys

from googleapiclient import discovery, errors
from oauth2client import file as oauth_file
from oauth2client import client, tools

# CLIENT_SECRETS is name of a file containing the OAuth 2.0 information
# <https://cloud.google.com/console#/project/803928506099/apiui>
CLIENT_SECRETS = os.path.join(os.path.dirname(__file__), 'client_secrets.json')
SESSION_STATE = os.path.join(os.path.dirname(__file__), 'SuspiciousLogger.dat')
GEOIP_DATA = os.path.join(os.path.dirname(__file__), 'GeoIP_data', 'GeoLiteCity.dat')
GEOIP = pygeoip.GeoIP(GEOIP_DATA, pygeoip.MMAP_CACHE)

def oauthorize(client_secrets, session_file):
    """Takes a path to a client_secrets.json and a session.dat file,
    performs an OAuth auth-flow and returns a service object."""
    # If the credentials don't exist or are invalid run through the native client
    # flow. The Storage object will ensure that if successful the good
    # credentials will get written back to the file.
    storage = oauth_file.Storage(session_file)
    credentials = storage.get()

    if credentials is None or credentials.invalid:
        # Prevent obnoxious browser window launching if our session is expired
        faux_parser = argparse.ArgumentParser(parents=[tools.argparser])
        flow_flags = faux_parser.parse_args("--noauth_local_webserver".split())
        scope = ['https://www.googleapis.com/auth/admin.reports.audit.readonly',
                 'https://www.googleapis.com/auth/admin.reports.usage.readonly']
        flow = client.flow_from_clientsecrets(client_secrets, scope=scope, \
                              message=tools.message_if_missing(client_secrets))
        credentials = tools.run_flow(flow, storage, flow_flags)

    # Create an httplib2.Http object to handle our HTTP requests and authorize it
    # with our good Credentials.
    http = httplib2.Http()
    http = credentials.authorize(http)

    return discovery.build('admin', 'reports_v1', http=http)

def main(argv):
    # Rudiments of exposing:
    # https://developers.google.com/admin-sdk/reports/v1/reference/activities/list
    parser = argparse.ArgumentParser()
    parser.add_argument('--userKey',
                        default="all",
                        help='Filter by username@example.com or "all".')
    parser.add_argument('--actorIpAddress',
                        help='An optional user IP address.')

    subparsers = parser.add_subparsers(help='Select events by user, IP or event.')
    subparsers.add_parser('list', help='List events by user or IP.')

    event_parser = subparsers.add_parser('events', \
                                         help='Filter log lines by event type \
                                         and additional filters.')
    event_parser.add_argument('eventName')
    event_parser.add_argument('--filters')

    # Parse the command-line flags.
    flags = parser.parse_args(argv[1:])

    # Construct the service object for the interacting with the Admin Reports API.
    service = oauthorize(CLIENT_SECRETS, SESSION_STATE)

    # Select the activities collection
    collection = service.activities()
    collection_filter = {'userKey': flags.userKey,
                         'actorIpAddress': flags.actorIpAddress,
                         'applicationName': 'login'}

    # probably a better way to do this with argparse
    if hasattr(flags, 'eventName'):
        collection_filter['eventName'] = flags.eventName
        collection_filter['filters'] = flags.filters

    try:
        req = collection.list(**collection_filter)
        # API access happens here
        response = req.execute()
    except client.AccessTokenRefreshError:
        print "Authorization has expired, re-authing next run."
    except errors.HttpError, e:
        print e
        print "The userKey='{userKey}' does not exist or is suspended".format(**collection_filter)
        sys.exit(-1)

    log_fmt = "{id[time]}  {ipAddress}  {region}, {country}  {actor[email]}  "
    log_fmt += "{events[0][name]}"
    ext_fmt = log_fmt + "  {login_type}"
    for entry in response['items']:
        # unpack non-redundant extra details such as login_type to the top level dict
        for event in entry['events']:
            if event.has_key('parameters'):
                params = event['parameters'].pop()
                if not entry.has_key(params['name']):
                    entry[params['name']] = params['value']

        location = GEOIP.record_by_addr(entry['ipAddress'])
        entry['country'] = location.get('country_code3', 'Unknown')
        entry['region'] = location.get('metro_code')
        if entry['region'] == None:
            entry['region'] = "{}, {}".format(location.get('city', 'Unknown'),
                                              location.get('region_code', 'Unknown'))
        if entry.has_key('login_type'):
            print ext_fmt.format(**entry)
        else:
            print log_fmt.format(**entry)

if __name__ == '__main__':
    main(sys.argv)
