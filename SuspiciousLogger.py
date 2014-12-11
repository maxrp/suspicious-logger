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
#
#
# For more information on the Admin Reports API you can visit:
#
#   https://developers.google.com/admin-sdk/reports/
#
# For more information on the Admin Reports API Python library surface you
# can visit:
#
#   https://developers.google.com/resources/api-libraries/documentation/admin/reports_v1/python/latest/
#
# For information on the Python Client Library visit:
#
#   https://developers.google.com/api-client-library/python/start/get_started

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
from oauth2client import file
from oauth2client import client
from oauth2client import tools

# (Google's) parser for command-line arguments pertaining to oauth-reauth.
parser = argparse.ArgumentParser(
    description=__doc__,
    formatter_class=argparse.RawDescriptionHelpFormatter,
    parents=[tools.argparser])

subparsers = parser.add_subparsers(help='Select events by user, IP or event.')

# Rudiments of exposing:
# https://developers.google.com/admin-sdk/reports/v1/reference/activities/list
parser.add_argument('--userKey',
                    default="all",
                    help='Filter by username@example.com or "all".')
parser.add_argument('--applicationName',
                    default='login',
                    required=True,
                    choices=['admin', 'docs', 'login'],
                    help='Filter by application: admin, docs or login. [default: %(default)s]',
                   )
parser.add_argument('--actorIpAddress',
                    help='An optional user IP address.')

list_parser = subparsers.add_parser('list',
                                    help='List events by user or IP.')

# This is technically part of the activities/list API too, but takes a couple
# very useful and very freeform options.
# 
# Predominantly intended for monitoring gmail settings changes & login events:
#   https://developers.google.com/admin-sdk/reports/v1/reference/activity-ref-appendix-a/admin-gmail-events
#   https://developers.google.com/admin-sdk/reports/v1/reference/activity-ref-appendix-a/login-event-names
event_parser = subparsers.add_parser('events',
                                      help='Filter log lines by event type and additional filters.')
event_parser.add_argument('eventName')
event_parser.add_argument('--filters')


# CLIENT_SECRETS is name of a file containing the OAuth 2.0 information for this
# application, including client_id and client_secret. You can see the Client ID
# and Client secret on the APIs page in the Cloud Console:
# <https://cloud.google.com/console#/project/803928506099/apiui>
CLIENT_SECRETS = os.path.join(os.path.dirname(__file__), 'client_secrets.json')

# Set up a Flow object to be used for authentication.
# Add one or more of the following scopes. PLEASE ONLY ADD THE SCOPES YOU
# NEED. For more information on using scopes please see
# <https://developers.google.com/+/best-practices>.
FLOW = client.flow_from_clientsecrets(CLIENT_SECRETS,
  scope=[
      'https://www.googleapis.com/auth/admin.reports.audit.readonly',
      'https://www.googleapis.com/auth/admin.reports.usage.readonly',
    ],
    message=tools.message_if_missing(CLIENT_SECRETS))

ACTIVITY_LOGLINE = "{id[time]}  {ipAddress}  {city}, {region}, {country}  {actor[email]}  {events[0][name]}"
GEOIP_DATA = os.path.join(os.path.dirname(__file__), 'GeoIP_data', 'GeoLiteCity.dat')
geoip = pygeoip.GeoIP(GEOIP_DATA, pygeoip.MMAP_CACHE)


def main(argv):
  # Parse the command-line flags.
  flags = parser.parse_args(argv[1:])

  # If the credentials don't exist or are invalid run through the native client
  # flow. The Storage object will ensure that if successful the good
  # credentials will get written back to the file.
  storage = file.Storage('SuspiciousLogger.dat')
  credentials = storage.get()
  if credentials is None or credentials.invalid:
    credentials = tools.run_flow(FLOW, storage, flags)

  # Create an httplib2.Http object to handle our HTTP requests and authorize it
  # with our good Credentials.
  http = httplib2.Http()
  http = credentials.authorize(http)

  # Construct the service object for the interacting with the Admin Reports API.
  service = discovery.build('admin', 'reports_v1', http=http)

  # Select the activities collection
  collection = service.activities()
  collectionFilter = {
                        'userKey':         flags.userKey,
                        'actorIpAddress':  flags.actorIpAddress,
                     }

  # probably a better way to do this with argparse
  if hasattr(flags, 'applicationName'):
    collectionFilter['applicationName'] = flags.applicationName
  if hasattr(flags, 'eventName'):
    collectionFilter['eventName'] = flags.eventName
    collectionFilter['filters'] = flags.filters

  try:
    req = collection.list(**collectionFilter)
    # API access happens here
    response = req.execute()
  except client.AccessTokenRefreshError:
    print ("The credentials have been revoked or expired, please re-run"
      "the application to re-authorize")
  except errors.HttpError, e:
    print e
    print "The userKey='{userKey}' does not exist or is suspended".format(**collectionFilter)
    sys.exit(-1)

  lines = []
  for entry in response['items']:
    location = geoip.record_by_addr(entry['ipAddress'])
    entry['country'] = location.get('country_code3', 'Unknown')
    entry['region'] = location.get('region_name', 'Unknown')
    entry['city'] = location.get('city', 'Unknown')
    print ACTIVITY_LOGLINE.format(**entry)

if __name__ == '__main__':
  main(sys.argv)
