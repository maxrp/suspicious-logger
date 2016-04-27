# Suspicious Logger

A CLI tool for examining Google Apps login events.

## Setup

To start you need [Maxmind's GeoIPlite data files][1]:

    ./GeoIP_data/update.sh

Then install the required Python modules:

    pip install -r requirements.txt

Next, you must provision OAuth credentials for the tool to run:
 1. Log in to GApps using a Superadmin account.
 1. Go to the [Google APIs Credentials page][2] and select "Create credentials".
 1. Select "OAuth Client ID" as the type of credential to create.
 1. For "application type" select "Other" and enter "SuspiciousLogger" or
    something which will clearly be associated with the purpose.
 1. The API credentials page will now yield a client_id and client_secret.
 1. Copy client_secrets.json.example to client_secrets.json.
 1. Copy and paste the client_id and client_secret into the matching fields in
    client_secrets.json.
 1. Finally, run a test query in the tool (i.e. 
    `./SuspiciousLogger.py ${USER}@example.com list`), this will lead to the
    tool presenting a URL.
        1. Copy and paste the URL into a browser session where your Superadmin
           account from step one is logged in.
        1. Accept the access requested by the tool, which will yield a code.
        1. Paste the code from the prior step into the SuspiciousLogger prompt.

NOTE: This API is *near* real-time but inexplicably lags behind email notices of
"suspicious logins" by days, weeks or even months. THANKS GOOGLE.


## Examples

List all logins from an IP:

    ./SuspiciousLogger.py 10.0.0.33 list

List all logins from a CIDR block:

    ./SuspiciousLogger.py 10.0.0.0/24 list

List all logins for a User:

    ./SuspiciousLogger.py foobar@example.com list

List only successful logins:

    ./SuspiciousLogger.py foobar@example.com events login_success

List all failed google_password events:

    ./SuspiciousLogger.py foobar@example.com events login_failure --filters 'login_type==google_password'

List all suspicious logins:

    ./SuspiciousLogger.py all events login_success --filters 'is_suspicious==true'

List all suspicious logins for a user:

    ./SuspiciousLogger.py foobar@example.com events login_success --filters 'is_suspicious==true'

List all suspicious SAML logins from a CIDR block:

    ./SuspiciousLogger.py 10.0.0.0/24 events login_success --filters 'login_type==saml,is_suspicious==true'

List all non-suspicious, non-SAML logins from a CIDR block:

    ./SuspiciousLogger.py 10.0.0.0/24 events login_success --filters 'login_type<>saml,is_suspicious<>true'

API Documentation
=============

The documentation for the google-api-python-client library is avialable here:

   https://developers.google.com/api-client-library/python/start/get_started

Documentation on some relevant event types for events and "--filters":

    https://developers.google.com/admin-sdk/reports/v1/reference/activity-ref-appendix-a/admin-gmail-events
    https://developers.google.com/admin-sdk/reports/v1/reference/activity-ref-appendix-a/login-event-names


[1]: http://dev.maxmind.com/geoip/
[2]: https://console.developers.google.com/apis/credentials
