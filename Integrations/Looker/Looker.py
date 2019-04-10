import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
from distutils.util import strtobool

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


def split_url(url):
    # validate url parameter format, extract port
    server, port = url.rsplit(':', 1)
    try:
        assert 0 < int(port) < 65536
    except (ValueError, AssertionError):
        return_error("Incorrect URL format. Use the following format: https://example.looker.com:19999\n"
                     "The default port for Looker API is 19999.")
    return server, port


''' GLOBALS/PARAMS '''
SESSION_VALIDITY_THRESHOLD = timedelta(minutes=5)

CLIENT_ID = demisto.params().get('client_id')
CLIENT_SECRET = demisto.params().get('client_secret')
# Remove trailing slash to prevent wrong URL path to service
SERVER = demisto.params()['url'][:-1] if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']
# Split URL to server and port
SERVER, PORT = split_url(SERVER)
# Should we use SSL
USE_SSL = not demisto.params().get('unsecure', False)
# How many time before the first fetch to retrieve incidents
FETCH_TIME = demisto.params().get('fetch_time', '3 days')
# Service base URL
BASE_URL = SERVER + '/api/3.0/'

handle_proxy()


''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, params=None, data=None):
    # A wrapper for requests lib to send our requests and handle requests and responses better
    res = requests.request(
        method,
        BASE_URL + url_suffix,
        verify=USE_SSL,
        params=params,
        data=data
    )
    # Handle error responses gracefully
    if res.status_code not in {200}:
        return_error('Error in API call to Looker [%d] - %s' % (res.status_code, res.reason))

    return res.json()


def get_new_token():
    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    response_json = http_request('GET', 'login', data=data)

    return {
        'token': response_json['access_token'],
        'expires': datetime.utcnow() + timedelta(seconds=int(response_json['expires_in']))
    }


def get_session_token():
    ic = demisto.getIntegrationContext()
    if CLIENT_ID not in ic or 'expires' not in ic[CLIENT_ID] \
            or ic[CLIENT_ID]['expires'] > datetime.utcnow() - SESSION_VALIDITY_THRESHOLD:
        ic[CLIENT_ID] = get_new_token()
        demisto.setIntegrationContext(ic)

    return ic[CLIENT_ID]['token']


def item_to_incident(item):
    incident = {}
    # Incident Title
    incident['name'] = 'Example Incident: ' + item.get('name')
    # Incident occurrence time, usually item creation date in service
    incident['occurred'] = item.get('createdDate')
    # The raw response from the service, providing full info regarding the item
    incident['rawJSON'] = json.dumps(item)
    return incident


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic get request to get item samples
    """
    http_request('GET', 'user')


def get_items_command():
    """
    Gets details about a items using IDs or some other filters
    """
    # Init main vars
    headers = []
    contents = []
    context = {}
    context_entries = []
    title = ''
    # Get arguments from user
    item_ids = argToList(demisto.args().get('item_ids', []))
    is_active = bool(strtobool(demisto.args().get('is_active', 'false')))
    limit = int(demisto.args().get('limit', 10))
    # Make request and get raw response
    items = get_items_request(item_ids, is_active)
    # Parse response into context & content entries
    if items:
        if limit:
            items = items[:limit]
        title = 'Example - Getting Items Details'

        for item in items:
            contents.append({
                'ID': item.get('id'),
                'Description': item.get('description'),
                'Name': item.get('name'),
                'Created Date': item.get('createdDate')
            })
            context_entries.append({
                'ID': item.get('id'),
                'Description': item.get('description'),
                'Name': item.get('name'),
                'CreatedDate': item.get('createdDate')
            })

        context['Example.Item(val.ID && val.ID === obj.ID)'] = context_entries

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, contents, removeNull=True),
        'EntryContext': context
    })


def get_items_request(item_ids, is_active):
    # The service endpoint to request from
    endpoint_url = 'items'
    # Dictionary of params for the request
    params = {
        'ids': item_ids,
        'isActive': is_active
    }
    # Send a request using our http_request wrapper
    response = http_request('GET', endpoint_url, params)
    # Check if response contains errors
    if response.get('errors'):
        return_error(response.get('errors'))
    # Check if response contains any data to parse
    if 'data' in response:
        return response.get('data')
    # If neither was found, return back empty results
    return {}


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))
TOKEN = get_session_token()
try:
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        test_module()
        demisto.results('ok')
    elif demisto.command() == 'example-get-items':
        # An example command
        get_items_command()

# Log exceptions
except Exception, e:
    LOG(e.message)
    LOG.print_log()
    raise