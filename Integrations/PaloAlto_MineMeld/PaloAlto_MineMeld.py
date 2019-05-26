import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import urllib.request
import urllib.error
from typing import Dict, List
import json
import base64
import ssl
import os.path
import os
import time
import re

# globals and constants
IPV4_CLASS = 'minemeld.ft.local.YamlIPv4FT'
IPV6_CLASS = 'minemeld.ft.local.YamlIPv6FT'
URL_CLASS = 'minemeld.ft.local.YamlURLFT'
DOMAIN_CLASS = 'minemeld.ft.local.YamlDomainFT'
LOCALDB_CLASS = 'minemeld.ft.localdb.Miner'
SUPPORTED_MINER_CLASSES = [IPV4_CLASS, IPV6_CLASS, URL_CLASS, DOMAIN_CLASS, LOCALDB_CLASS]
SERVER_URL = demisto.params()['url']
USERNAME = demisto.params()['credentials']['identifier']
PASSWORD = demisto.params()['credentials']['password']
WHITELISTS = argToList(demisto.params().get('whitelist')) if demisto.params().get('whitelist') else []
BLACKLISTS = argToList(demisto.params().get('blacklist')) if demisto.params().get('blacklist') else []

if not isinstance(WHITELISTS, list) or not isinstance(BLACKLISTS, list):
    return_error(
        'Either blacklist or whitelist params were wrongfully configured - expecting comma separated list,'
        'ex: miner_a,miner_b,miner_c')


# API class
class APIClient(object):

    def __init__(self, url_, username, password, capath):
        self.url = url_
        self.username = username
        self.password = password

        self.cafile = None
        self.capath = None
        self.context = None
        self.data_file_type = None

        if capath is None:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE
        else:
            if os.path.isfile(capath):
                self.cafile = capath
            elif os.path.isdir(capath):
                self.capath = capath
            else:
                return_error('CA path should be a file or a directory: {capath}')

    def _call_api(self, uri, data=None, headers=None, method=None):
        if headers is None:
            headers = {}

        api_url = urljoin(self.url, uri)
        basic_authorization = base64.b64encode(f'{self.username}:{self.password}')  # type: ignore
        headers['Authorization'] = f'Basic {basic_authorization}'
        api_request = urllib.request.Request(api_url, headers=headers, method=method)

        try:
            result = urllib.request.urlopen(
                api_request,
                data=data,
                timeout=30,
                capath=self.capath,
                cafile=self.cafile,
                context=self.context
            )
            content = result.read()
            result.close()

        except urllib.error.HTTPError as e:
            demisto.debug(json.dumps(e))
            if e.code != 400:
                raise
            content = b'{ "result":[] }'

        return content

    def get_all_nodes(self):
        content = self._call_api('/status/minemeld')
        minemeld_status = json.loads(content)['result']

        return minemeld_status

    def validate_miner(self, miner):
        content = self._call_api('/status/minemeld')
        minemeld_status = json.loads(content)['result']

        for node in minemeld_status:
            if node['name'] == miner:
                if not node['class'] in SUPPORTED_MINER_CLASSES:
                    if node['class'] == LOCALDB_CLASS:
                        class_ = 'localdb'
                    else:
                        class_ = 'yaml'
                    return_error('Unsupported miner class of type: {}'.format(class_))
                return True

        return_error('Miner {miner} was not found in miners list')
        return False

    def retrieve_miner(self, miner):
        content = self._call_api('/config/data/{}_indicators?t={}'.format(miner, self.data_file_type))
        return json.loads(content)['result']

    def upload(self, miner, data):
        if self.data_file_type == 'localdb':
            ts = time.time()
            self._call_api(
                f'/config/data/{miner}_indicators/append?_{ts}&h={miner}&t={self.data_file_type}',
                data=data,
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            return

        self._call_api(
            '/config/data/{miner}_indicators?h={miner}',
            data=data,
            headers={'Content-Type': 'application/json'},
            method='PUT'
        )


# system funcs
def get_miner_list(minemeld_client, miner):
    minemeld_client.validate_miner(miner)
    miner_list = minemeld_client.retrieve_miner(miner)
    return miner_list


def add_indicator_to_miner(minemeld_client, miner, indicators, type_, comment=''):
    miner_list = get_miner_list(minemeld_client, miner)
    updated_miner_list = {
        e['indicator']: json.dumps(e, sort_keys=True) for e in miner_list
    }

    if not isinstance(indicators, list):
        indicators = indicators.split(',')

    if type_ is False:
        type_ = ''

    for indicator in indicators:
        if minemeld_client.data_file_type == 'localdb':
            request_params = {
                'indicator': indicator,
                'comment': comment,
                'type': type_,
                'ttl': 'disabled'
            }
        else:
            request_params = {
                'indicator': indicator,
                'comment': comment
            }
        updated_miner_list[indicator] = json.dumps(request_params)

    values = ','.join(updated_miner_list.values())
    minemeld_client.upload(miner, '[{}]'.format(values))


def remove_indicator_from_miner(minemeld_client, miner, indicators):
    miner_list = get_miner_list(minemeld_client, miner)
    updated_miner_list = {
        e['indicator']: json.dumps(e, sort_keys=True) for e in miner_list
    }

    if not isinstance(indicators, list):
        indicators = indicators.split(',')

    if minemeld_client.data_file_type == 'localdb':
        # check that all indicators to remove are on localdb miner
        miner_list_indicators = [o['indicator'] for o in miner_list]
        contain_all_indicators = all(elem in miner_list_indicators for elem in indicators)
        if not contain_all_indicators:
            return_error('Did not find all indicators on miner {miner}')

        for indicator in indicators:
            request_params = {
                'indicator': indicator,
                'type': json.loads(updated_miner_list[indicator])['type'],
                'ttl': -1
            }
            updated_miner_list[indicator] = json.dumps(request_params)
    else:
        # remove indicator from miner, if nothing was removed, indicator not on miner
        for indicator in indicators:
            indicator_from_list = updated_miner_list.pop(indicator, None)
            if not indicator_from_list:
                return_error('Did not find indicator {indicator} on miner {miner}')

    values = ','.join(updated_miner_list.values())
    minemeld_client.upload(miner, '[{}]'.format(values))


def get_indicators_from_miner(minemeld_client, miner_name, indicator_value=False):
    result_indicator = []  # type: List
    miner_list = get_miner_list(minemeld_client, miner_name)
    for indicator in miner_list:
        if indicator['indicator'] == indicator_value or indicator_value is False:
            indicator['miner'] = miner_name
            result_indicator.append(indicator)

    return result_indicator


def get_indicator_type(indicator):
    indicator_type = ''

    if not indicator_type:
        url_ = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*(),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
                          indicator)  # guardrails-disable-line
        if url_:
            indicator_type = 'URL'

    if not indicator_type:
        ipv4 = re.findall(
            '^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}'
            '(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$',
            indicator)
        if ipv4 and not indicator_type:
            indicator_type = 'IPv4'

    if not indicator_type:
        ipv6 = re.findall(
            '^(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}'
            '|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}'
            '(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}'
            '(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}'
            '(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}'
            '(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}'
            '(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::'
            '(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}'
            '|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|'
            '(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}'
            '(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}'
            '(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})'
            '?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|'
            '(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}'
            '(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|'
            '(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|'
            '(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}'
            '(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|'
            '(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|'
            '(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)$',
            indicator)
        if ipv6:
            indicator_type = 'IPv6'

    if not indicator_type:
        file_ = get_hash_type(indicator)
        if file_ != 'Unknown':
            indicator_type = file_

    return indicator_type


# commands
def domain():
    domain_ = demisto.args().get('domain')
    # output vars
    result_indicator = []  # type: List
    miner_name = ''
    dbotscore = 0

    # search for indicator in all miners defined by user
    for blacklist in BLACKLISTS:
        result_indicator = get_indicators_from_miner(blacklist, domain_)
        if result_indicator:
            dbotscore = 3
            break
    if dbotscore != 3:
        for whitelist in WHITELISTS:
            result_indicator = get_indicators_from_miner(whitelist, domain_)
            if result_indicator:
                dbotscore = 1
                break

    # start building output and context
    dbotscore_list = {
        'Indicator': domain_,
        'Type': 'domain',
        'Vendor': 'Palo Alto MineMeld',
        'Score': dbotscore
    }

    if result_indicator:
        miner_name = result_indicator[0]['miner']
        # add only malicious to context
        if dbotscore == 3:
            indicator_context_data = {
                'MineMeld': {
                    'Indicators': result_indicator
                },
                'Malicious': {
                    'Vendor': 'Palo Alto MineMeld',
                    'Description': 'Indicator was found in MineMeld\'s blacklist: {miner_name}'
                },
                'Name': domain_
            }
        else:
            indicator_context_data = {
                'MineMeld': {
                    'Miner': {'name': miner_name},
                    'Indicators': result_indicator
                },
                'Name': domain_
            }

        entry_context = {
            'DBotScore': dbotscore_list,
            outputPaths['domain']: indicator_context_data,
            'MineMeld.Indicators(val.indicator == obj.indicator)': result_indicator,
            'MineMeld.Miner(val.name == obj.name)': {'name': miner_name},
        }
        result_text = 'MineMeld Domain found at miner: {miner_name}'
    else:
        result_text = 'MineMeld Domain severity - unknown'
        entry_context = {
            'DBotScore': dbotscore_list,
            'MineMeld.Indicators(val.indicator == obj.indicator)': result_indicator,
            'MineMeld.Miner(val.name == obj.name)': {'name': miner_name},
        }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': result_indicator,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(result_text, result_indicator, ['indicator', 'type', 'comment']),
        'EntryContext': entry_context
    })


def url():
    url_ = demisto.args().get('url')
    # output vars
    result_indicator = []  # type: List
    miner_name = ''
    dbotscore = 0

    # search for indicator in all miners defined by user
    for blacklist in BLACKLISTS:
        result_indicator = get_indicators_from_miner(blacklist, url_)
        if result_indicator:
            dbotscore = 3
            break
    if dbotscore != 3:
        for whitelist in WHITELISTS:
            result_indicator = get_indicators_from_miner(whitelist, url_)
            if result_indicator:
                dbotscore = 1
                break

    # start building output and context
    dbotscore_list = {
        'Indicator': url_,
        'Type': 'url',
        'Vendor': 'Palo Alto MineMeld',
        'Score': dbotscore
    }

    if result_indicator:
        miner_name = result_indicator[0]['miner']
        # add only malicious to context
        if dbotscore == 3:
            indicator_context_data = {
                'MineMeld': {
                    'Indicators': result_indicator
                },
                'Malicious': {
                    'Vendor': 'Palo Alto MineMeld',
                    'Description': 'Indicator was found in MineMeld\'s blacklist: {miner_name}'
                },
                'Data': url
            }
        else:
            indicator_context_data = {
                'MineMeld': {
                    'Miner': {'name': miner_name},
                    'Indicators': result_indicator
                },
                'Data': url_
            }

        entry_context = {
            'DBotScore': dbotscore_list,
            outputPaths['url']: indicator_context_data,
            'MineMeld.Indicators(val.indicator == obj.indicator)': result_indicator,
            'MineMeld.Miner(val.name == obj.name)': {'name': miner_name},
        }
        result_text = 'MineMeld URL found at miner: {miner_name}'
    else:
        result_text = 'MineMeld URL severity - unknown'
        entry_context = {
            'DBotScore': dbotscore_list,
            'MineMeld.Indicators(val.indicator == obj.indicator)': result_indicator,
            'MineMeld.Miner(val.name == obj.name)': {'name': miner_name},
        }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': result_indicator,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(result_text, result_indicator, ['indicator', 'type', 'comment']),
        'EntryContext': entry_context
    })


def file():
    file_ = demisto.args().get('file')
    # output vars
    result_indicator = []  # type: List
    miner_name = ''
    dbotscore = 0

    # search for indicator in all miners defined by user
    for blacklist in BLACKLISTS:
        result_indicator = get_indicators_from_miner(blacklist, file_)
        if result_indicator:
            dbotscore = 3
            break
    if dbotscore != 3:
        for whitelist in WHITELISTS:
            result_indicator = get_indicators_from_miner(whitelist, file_)
            if result_indicator:
                dbotscore = 1
                break

    # start building output and context
    dbotscore_list = {
        'Indicator': file_,
        'Type': 'hash',
        'Vendor': 'Palo Alto MineMeld',
        'Score': dbotscore
    }

    if result_indicator:
        miner_name = result_indicator[0]['miner']
        # add only malicious to context
        if dbotscore == 3:
            indicator_context_data = {
                'MineMeld': {
                    'Indicators': result_indicator
                },
                'Malicious': {
                    'Vendor': 'Palo Alto MineMeld',
                    'Description': 'Indicator was found in MineMeld\'s blacklist: {miner_name}'
                },
                get_hash_type(file_): file_
            }
        else:
            indicator_context_data = {
                'MineMeld': {
                    'Miner': {'name': miner_name},
                    'Indicators': result_indicator
                },
                get_hash_type(file_): file_
            }

        entry_context = {
            'DBotScore': dbotscore_list,
            outputPaths['file']: indicator_context_data,
            'MineMeld.Indicators(val.indicator == obj.indicator)': result_indicator,
            'MineMeld.Miner(val.name == obj.name)': {'name': miner_name},
        }
        result_text = 'MineMeld File found at miner: {miner_name}'
    else:
        result_text = 'MineMeld File severity - unknown'
        entry_context = {
            'DBotScore': dbotscore_list,
            'MineMeld.Indicators(val.indicator == obj.indicator)': result_indicator,
            'MineMeld.Miner(val.name == obj.name)': {'name': miner_name},
        }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': result_indicator,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(result_text, result_indicator, ['indicator', 'type', 'comment']),
        'EntryContext': entry_context
    })


def ip():
    ip_ = demisto.args().get('ip')
    # output vars
    result_indicator = []  # type: List
    miner_name = ''
    dbotscore = 0

    # search for indicator in all miners defined by user
    for blacklist in BLACKLISTS:
        result_indicator = get_indicators_from_miner(blacklist, ip_)
        if result_indicator:
            dbotscore = 3
            break
    if dbotscore != 3:
        for whitelist in WHITELISTS:
            result_indicator = get_indicators_from_miner(whitelist, ip_)
            if result_indicator:
                dbotscore = 1
                break

    # start building output and context
    dbotscore_list = {
        'Indicator': ip_,
        'Type': 'ip',
        'Vendor': 'Palo Alto MineMeld',
        'Score': dbotscore
    }

    if result_indicator:
        miner_name = result_indicator[0]['miner']
        # add only malicious to context
        if dbotscore == 3:
            indicator_context_data = {
                'MineMeld': {
                    'Indicators': result_indicator
                },
                'Malicious': {
                    'Vendor': 'Palo Alto MineMeld',
                    'Description': 'Indicator was found in MineMeld\'s blacklist: {miner_name}'
                },
                'Address': ip_
            }
        else:
            indicator_context_data = {
                'MineMeld': {
                    'Miner': {'name': miner_name},
                    'Indicators': result_indicator
                },
                'Address': ip_
            }

        entry_context = {
            'DBotScore': dbotscore_list,
            outputPaths['ip']: indicator_context_data,
            'MineMeld.Indicators(val.indicator == obj.indicator)': result_indicator,
            'MineMeld.Miner(val.name == obj.name)': {'name': miner_name},
        }
        result_text = 'MineMeld IP found at miner: {miner_name}'
    else:
        result_text = 'MineMeld IP severity - unknown'
        entry_context = {
            'DBotScore': dbotscore_list,
            'MineMeld.Indicators(val.indicator == obj.indicator)': result_indicator,
            'MineMeld.Miner(val.name == obj.name)': {'name': miner_name},
        }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': result_indicator,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(result_text, result_indicator, ['indicator', 'type', 'comment']),
        'EntryContext': entry_context
    })


def get_all_miner_names(minemeld_client):
    miners_list = minemeld_client.get_all_nodes()
    supported_miners = []

    for miner in miners_list:
        if miner['class'] in SUPPORTED_MINER_CLASSES:
            supported_miners.append({
                'name': miner['name'],
                'indicators': miner['length'],
                'class': miner['class']
            })

    if supported_miners:
        result_text = 'Miners found: '
    else:
        result_text = 'No miners found'

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': supported_miners,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(result_text, supported_miners, ['name', 'indicators', 'class']),
        'EntryContext': {
            'MineMeld.Miner(val.name == obj.name)': supported_miners
        }
    })


def get_indicator_from_miner(minemeld_client):
    miner_name = demisto.args().get('miner')
    indicator = demisto.args().get('indicator')

    supported_miners = get_indicators_from_miner(minemeld_client, miner_name, indicator)

    if supported_miners:
        result_text = 'Items found at miner: {miner_name}'
    else:
        result_text = 'No items found at miner'

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': supported_miners,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(result_text, supported_miners, ['indicator', 'type', 'comment']),
        'EntryContext': {
            'MineMeld.Miner(val.name == obj.name)': {'name': miner_name},
            'MineMeld.Indicators(val.miner == obj.miner && val.indicator == obj.indicator)': supported_miners
        }
    })


def retrieve_miner_indicators(minemeld_client):
    miner_name = demisto.args().get('miner')
    result_list = []  # type: List[str]
    markdown_headers = ['indicator', 'comment', 'type']
    miners_context = []  # type: List[Dict]

    if miner_name == 'all':
        markdown_headers.insert(0, 'miner')
        miners_list = minemeld_client.get_all_nodes()

        for miner in miners_list:
            if miner['class'] in SUPPORTED_MINER_CLASSES:
                miners_context.append(
                    {
                        'name': miner['name'],
                        'class': miner['class']
                    }
                )
                miner_list = get_indicators_from_miner(minemeld_client, miner['name'])
                result_list.extend(miner_list)

    else:
        result_list = get_indicators_from_miner(minemeld_client, miner_name)
        miners_context.append({'name': miner_name})

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': result_list,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Minemeld indicators {miner_name}', result_list, markdown_headers),
        'EntryContext': {
            'MineMeld.Miner(val.name == obj.name)': miners_context,
            'MineMeld.Indicators(val.miner == obj.miner && val.indicator == obj.indicator)': result_list
        }
    })


def update_miner(minemeld_client):
    miner = demisto.args().get('miner')
    indicators = argToList(demisto.args().get('indicator'))
    if len(indicators) < 1:
        return_error('Insert at least 1 indicator')
    type_ = demisto.args().get('type', get_indicator_type(indicators[0]))
    comment = demisto.args().get('comment', '')

    for indicator in indicators:
        if ' ' in indicator:
            return_error("Don't use space in indicator")

    if demisto.command() == 'minemeld-add-to-miner':
        add_indicator_to_miner(minemeld_client, miner, indicators, type_, comment)
    elif demisto.command() == 'minemeld-remove-from-miner':
        remove_indicator_from_miner(minemeld_client, miner, indicators)

    demisto.results('Performed action successfully')


def test(minemeld_client):
    if minemeld_client.get_all_nodes():
        demisto.results('ok')


''' EXECUTION '''


def main():
    LOG('command is %s' % (demisto.command(),))

    # Remove proxy if not set to true in params
    handle_proxy()

    minemeld_client = APIClient(
        url_=SERVER_URL,
        username=USERNAME,
        password=PASSWORD,
        capath=None
    )

    try:
        if demisto.command() == 'test-module':
            test(minemeld_client)

        elif demisto.command() == 'minemeld-add-to-miner' or demisto.command() == 'minemeld-remove-from-miner':
            update_miner(minemeld_client)

        elif demisto.command() == 'minemeld-retrieve-miner':
            retrieve_miner_indicators(minemeld_client)

        elif demisto.command() == 'minemeld-get-indicator-from-miner':
            get_indicator_from_miner(minemeld_client)

        elif demisto.command() == 'minemeld-get-all-miners-names':
            get_all_miner_names(minemeld_client)

        elif demisto.command() == 'domain':
            domain()

        elif demisto.command() == 'url':
            url()

        elif demisto.command() == 'file':
            file()

        elif demisto.command() == 'ip':
            ip()

    except Exception as ex:
        return_error(str(ex))

    finally:
        LOG.print_log()


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
