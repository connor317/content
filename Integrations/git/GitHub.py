import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
from datetime import datetime, timedelta

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

USER = demisto.params().get('user')
TOKEN = demisto.params().get('token')
BASE_URL = demisto.params().get('url')
REP = demisto.params().get('repository')
USE_SSL = not demisto.params().get('insecure', False)
FETCH_TIME = demisto.params().get('fetch_time', '30 days')

USER_SUFFIX = '/repos/{}/{}'.format(USER, REP)
ISSUE_SUFFIX = USER_SUFFIX + '/issues'
RELEASE_SUFFIX = USER_SUFFIX + '/releases'

# Headers to be sent in requests
HEADERS = {
    'Authorization': "Bearer " + TOKEN
}


''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, params=None, data=None):
    # A wrapper for requests lib to send our requests and handle requests and responses better
    res = requests.request(
        method,
        BASE_URL + url_suffix,
        verify=USE_SSL,
        params=params,
        data=json.dumps(data),
        headers=HEADERS
    )
    # Handle error responses gracefully
    if res.status_code >= 400:
        return_error('Error in API call to Example Integration [%d] - %s' % (res.status_code, res.reason))
    try:
        return res.json()
    except Exception as excep:
        return_error('Error in HTTP request - {}'.format(str(excep)))


def data_formatting(title, body, milestone, labels, assignees, state):
    """This method creates a dictionary to be used as "data" field in an http request."""
    data = {}
    if title is not None:
        data['title'] = title

    if body is not None:
        data['body'] = body

    if state is not None:
        data['state'] = state

    if milestone is not None:
        data['milestone'] = int(milestone)

    if labels is not None:
        data['labels'] = labels.split(',')

    if assignees is not None:
        data['assignees'] = assignees.split(',')

    return data


def context_create_issue(response, issue):
    """ Create GitHub.Issue EntryContext and results to be printed in Demisto
    Args:
        response (dict): The raw HTTP response to be inserted to the 'Contents' field
        issue (dict or list): A dictionary or a list of dictionaries formatted for Demisto results

    """
    ec = {
        'GitHub.Issue(val.Repository == obj.Repository && val.ID == obj.ID)': issue
    }
    return_outputs(tableToMarkdown("Issues:", issue), ec, response)


def issue_format(issue):
    """ Get a HTTP response containing an issue and creates a dictionary with selected fields representing an issue in
     Demisto.
    Args:
        issue (dict): An HTTP response representing an issue, formatted as a dictionary
    Returns:
        Returns a dictionary representing an issue in Demisto
    """
    form = {
        'ID': issue.get('number'),
        'Repository': issue.get('repository_url'),
        'Title': issue.get('title'),
        'Body': issue.get('body'),
        'State': issue.get('state')
    }
    return form


def create_issue_table(issue_list, response):
    """ Get an HTTP response and a list containing several issues, sends each issue to be reformatted.

    Args:
        issue_list(list): derived from the HTTP response
        response (dict):A raw HTTP response sent for 'Contents' field in context

    Returns:
        The issues are sent to Demisto as a list

    """
    issue_table = []
    for issue in issue_list:
        issue_table.append(issue_format(issue))

    context_create_issue(response, issue_table)


''' REQUESTS FUNCTIONS '''


def create_issue(title, body, milestone, labels, assignees):
    if title == "":
        return_error("Error: No title given for created issue")

    data = data_formatting(title=title,
                           body=body,
                           milestone=milestone,
                           labels=labels,
                           assignees=assignees,
                           state=None)

    response = http_request(method='POST',
                            url_suffix=ISSUE_SUFFIX,
                            data=data)
    return response


def close_issue(issue_number):
    response = http_request(method='PATCH',
                            url_suffix=ISSUE_SUFFIX + '/{}'.format(str(issue_number)),
                            data={'state': 'closed'})
    return response


def update_issue(issue_number, title, body, state, milestone, labels, assign):
    data = data_formatting(title=title,
                           body=body,
                           milestone=milestone,
                           labels=labels,
                           assignees=assign,
                           state=state)

    response = http_request(method='PATCH',
                            url_suffix=ISSUE_SUFFIX + '/{}'.format(str(issue_number)),
                            data=data)

    if response.get('errors'):
        return_error(response.get('errors'))

    return response


def list_all_issue(only_open):
    params = {}  # type: dict
    if only_open == 'true':
        params = {'state': 'all'}

    response = http_request(method='GET',
                            url_suffix=ISSUE_SUFFIX,
                            params=params)
    return response


def search_issue(query):
    response = http_request(method='GET',
                            url_suffix='/search/issues',
                            params={'q': query})

    if response.get('errors'):
        return_error(response.get('errors'))

    return response


def get_download_count():
    response = http_request(method='GET',
                            url_suffix=RELEASE_SUFFIX)

    count_per_release = []
    for release in response:
        total_download_count = 0
        for asset in release.get('assets', []):
            total_download_count = total_download_count + asset['download_count']

        release_info = {
            'URL': release.get('url'),
            'Download_count': total_download_count
        }
        count_per_release.append(release_info)

    ec = {
        'GitHub.Release( val.URL == obj.URL )': count_per_release
    }
    return_outputs(tableToMarkdown('Releases:', count_per_release), ec, response)


''' COMMANDS MANAGER / SWITCH PANEL '''


def create_command():
    args = demisto.args()
    response = create_issue(args.get('title'), args.get('body'),
                            args.get('milestone'), args.get('labels'), args.get('assignees'))
    issue = issue_format(response)
    context_create_issue(response, issue)


def close_command():
    issue_number = demisto.args().get('issue_number')
    response = close_issue(issue_number)
    issue = issue_format(response)
    context_create_issue(response, issue)


def update_command():
    args = demisto.args()
    response = update_issue(args['issue_number'], args.get('title'), args.get('body'), args.get('state'),
                            args.get('milestone'), args.get('labels'), args.get('assignees'))
    issue = issue_format(response)
    context_create_issue(response, issue)


def list_all_command():
    only_open = demisto.args().get('all')
    response = list_all_issue(only_open)
    create_issue_table(response, response)


def search_command():
    q = demisto.args().get('query')
    response = search_issue(q)
    create_issue_table(response['items'], response)


def fetch_incidents_command():
    last_run = demisto.getLastRun()
    if last_run and 'start_time' in last_run:
        start_time = datetime.strptime(last_run.get('start_time'), '%Y-%m-%dT%H:%M:%SZ')

    else:
        start_time = datetime.now() - timedelta(days=int(FETCH_TIME))

    last_time = start_time
    issue_list = http_request(method='GET',
                              url_suffix=ISSUE_SUFFIX,
                              params={'state': 'all'})

    incidents = []
    for issue in issue_list:
        updated_at_str = issue.get('updated_at')
        updated_at = datetime.strptime(updated_at_str, '%Y-%m-%dT%H:%M:%SZ')
        if updated_at > start_time:
            inc = {
                'name': issue.get('url'),
                'occurred': updated_at_str,
                'rawJSON': json.dumps(issue)
            }
            incidents.append(inc)
            if updated_at > last_time:
                last_time = updated_at

    demisto.setLastRun({'start_time': datetime.strftime(last_time, '%Y-%m-%dT%H:%M:%SZ')})
    demisto.incidents(incidents)


'''EXECUTION'''
handle_proxy()
LOG('command is %s' % (demisto.command(),))
try:
    if demisto.command() == 'test-module':
        issue_list = http_request(method='GET',
                                  url_suffix=ISSUE_SUFFIX,
                                  params={'state': 'all'})
        demisto.results("ok")
    elif demisto.command() == 'fetch-incidents':
        fetch_incidents_command()
    elif demisto.command() == 'GitHub-create-issue':
        create_command()
    elif demisto.command() == 'GitHub-close-issue':
        close_command()
    elif demisto.command() == 'GitHub-update-issue':
        update_command()
    elif demisto.command() == 'GitHub-list-all-issues':
        list_all_command()
    elif demisto.command() == 'GitHub-search-issues':
        search_command()
    elif demisto.command() == 'GitHub-get-download-count':
        get_download_count()

except Exception as e:
    LOG(e.message)
    LOG.print_log()
    raise
