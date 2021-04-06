# -*- coding: utf-8 -*-
"""
shodan.client
~~~~~~~~~~~~~

This module implements the Shodan API.

:copyright: (c) 2014- by John Matherly
"""
import time

from thirdparty import requests
import json

from .exception import APIError
from .helpers import api_request, create_facet_string
from .stream import Stream


# Try to disable the SSL warnings in urllib3 since not everybody can install
# C extensions. If you're able to install C extensions you can try to run:
#
# pip install requests[security]
#
# Which will download libraries that offer more full-featured SSL classes
# pylint: disable=E1101
try:
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass

# Define a basestring type if necessary for Python3 compatibility
try:
    basestring
except NameError:
    basestring = str


class Shodan:
    """Wrapper around the Shodan REST and Streaming APIs

    :param key: The Shodan API key that can be obtained from your account page (https://account.shodan.io)
    :type key: str
    :ivar exploits: An instance of `shodan.Shodan.Exploits` that provides access to the Exploits REST API.
    :ivar stream: An instance of `shodan.Shodan.Stream` that provides access to the Streaming API.
    """

    class Data:

        def __init__(self, parent):
            self.parent = parent

        def list_datasets(self):
            """Returns a list of datasets that the user has permission to download.

            :returns: A list of objects where every object describes a dataset
            """
            return self.parent._request('/shodan/data', {})

        def list_files(self, dataset):
            """Returns a list of files that belong to the given dataset.

            :returns: A list of objects where each object contains a 'name', 'size', 'timestamp' and 'url'
            """
            return self.parent._request('/shodan/data/{}'.format(dataset), {})

    class Dns:

        def __init__(self, parent):
            self.parent = parent

        def domain_info(self, domain, history=False, type=None, page=1):
            """Grab the DNS information for a domain.
            """
            args = {
                'page': page,
            }
            if history:
                args['history'] = history
            if type:
                args['type'] = type
            return self.parent._request('/dns/domain/{}'.format(domain), args)

    class Notifier:

        def __init__(self, parent):
            self.parent = parent
        
        def create(self, provider, args, description=None):
            """Get the settings for the specified notifier that a user has configured.

            :param provider: Provider name
            :type provider: str
            :param args: Provider arguments
            :type args: dict
            :param description: Human-friendly description of the notifier
            :type description: str
            :returns: dict -- fields are 'success' and 'id' of the notifier
            """
            args['provider'] = provider

            if description:
                args['description'] = description
            
            return self.parent._request('/notifier', args, method='post')
        
        def edit(self, nid, args):
            """Get the settings for the specified notifier that a user has configured.

            :param nid: Notifier ID
            :type nid: str
            :param args: Provider arguments
            :type args: dict
            :returns: dict -- fields are 'success' and 'id' of the notifier
            """
            return self.parent._request('/notifier/{}'.format(nid), args, method='put')
        
        def get(self, nid):
            """Get the settings for the specified notifier that a user has configured.

            :param nid: Notifier ID
            :type nid: str
            :returns: dict -- object describing the notifier settings
            """
            return self.parent._request('/notifier/{}'.format(nid), {})

        def list_notifiers(self):
            """Returns a list of notifiers that the user has added.

            :returns: A list of notifierse that are available on the account
            """
            return self.parent._request('/notifier', {})

        def list_providers(self):
            """Returns a list of supported notification providers.

            :returns: A list of providers where each object describes a provider
            """
            return self.parent._request('/notifier/provider', {})
        
        def remove(self, nid):
            """Delete the provided notifier.

            :param nid: Notifier ID
            :type nid: str
            :returns: dict -- 'success' set to True if action succeeded
            """
            return self.parent._request('/notifier/{}'.format(nid), {}, method='delete')

    class Tools:

        def __init__(self, parent):
            self.parent = parent

        def myip(self):
            """Get your current IP address as seen from the Internet.

            :returns: str -- your IP address
            """
            return self.parent._request('/tools/myip', {})

    class Exploits:

        def __init__(self, parent):
            self.parent = parent

        def search(self, query, page=1, facets=None):
            """Search the entire Shodan Exploits archive using the same query syntax
            as the website.

            :param query: The exploit search query; same syntax as website.
            :type query: str
            :param facets: A list of strings or tuples to get summary information on.
            :type facets: str
            :param page: The page number to access.
            :type page: int
            :returns: dict -- a dictionary containing the results of the search.
            """
            query_args = {
                'query': query,
                'page': page,
            }
            if facets:
                query_args['facets'] = create_facet_string(facets)

            return self.parent._request('/api/search', query_args, service='exploits')

        def count(self, query, facets=None):
            """Search the entire Shodan Exploits archive but only return the total # of results,
            not the actual exploits.

            :param query: The exploit search query; same syntax as website.
            :type query: str
            :param facets: A list of strings or tuples to get summary information on.
            :type facets: str
            :returns: dict -- a dictionary containing the results of the search.

            """
            query_args = {
                'query': query,
            }
            if facets:
                query_args['facets'] = create_facet_string(facets)

            return self.parent._request('/api/count', query_args, service='exploits')

    class Labs:

        def __init__(self, parent):
            self.parent = parent

        def honeyscore(self, ip):
            """Calculate the probability of an IP being an ICS honeypot.

            :param ip: IP address of the device
            :type ip: str

            :returns: int -- honeyscore ranging from 0.0 to 1.0
            """
            return self.parent._request('/labs/honeyscore/{}'.format(ip), {})

    class Organization:

        def __init__(self, parent):
            self.parent = parent

        def add_member(self, user, notify=True):
            """Add the user to the organization.

            :param user: username or email address
            :type user: str
            :param notify: whether or not to send the user an email notification
            :type notify: bool

            :returns: True if it succeeded and raises an Exception otherwise
            """
            return self.parent._request('/org/member/{}'.format(user), {
                'notify': notify,
            }, method='PUT')['success']

        def info(self):
            """Returns general information about the organization the current user is a member of.
            """
            return self.parent._request('/org', {})

        def remove_member(self, user):
            """Remove the user from the organization.

            :param user: username or email address
            :type user: str

            :returns: True if it succeeded and raises an Exception otherwise
            """
            return self.parent._request('/org/member/{}'.format(user), {}, method='DELETE')['success']

    def __init__(self, key, proxies=None):
        """Initializes the API object.

        :param key: The Shodan API key.
        :type key: str
        :param proxies: A proxies array for the requests library, e.g. {'https': 'your proxy'}
        :type proxies: dict
        """
        self.api_key = key
        self.base_url = 'https://api.shodan.io'
        self.base_exploits_url = 'https://exploits.shodan.io'
        self.data = self.Data(self)
        self.dns = self.Dns(self)
        self.exploits = self.Exploits(self)
        self.labs = self.Labs(self)
        self.notifier = self.Notifier(self)
        self.org = self.Organization(self)
        self.tools = self.Tools(self)
        self.stream = Stream(key, proxies=proxies)
        self._session = requests.Session()
        if proxies:
            self._session.proxies.update(proxies)
            self._session.trust_env = False

    def _request(self, function, params, service='shodan', method='get'):
        """General-purpose function to create web requests to SHODAN.

        Arguments:
            function  -- name of the function you want to execute
            params    -- dictionary of parameters for the function

        Returns
            A dictionary containing the function's results.

        """
        # Add the API key parameter automatically
        params['key'] = self.api_key

        # Determine the base_url based on which service we're interacting with
        base_url = {
            'shodan': self.base_url,
            'exploits': self.base_exploits_url,
        }.get(service, 'shodan')

        # Send the request
        try:
            method = method.lower()
            if method == 'post':
                data = self._session.post(base_url + function, params)
            elif method == 'put':
                data = self._session.put(base_url + function, params=params)
            elif method == 'delete':
                data = self._session.delete(base_url + function, params=params)
            else:
                data = self._session.get(base_url + function, params=params)
        except Exception:
            raise APIError('Unable to connect to Shodan')

        # Check that the API key wasn't rejected
        if data.status_code == 401:
            try:
                # Return the actual error message if the API returned valid JSON
                error = data.json()['error']
            except Exception as e:
                # If the response looks like HTML then it's probably the 401 page that nginx returns
                # for 401 responses by default
                if data.text.startswith('<'):
                    error = 'Invalid API key'
                else:
                    # Otherwise lets raise the error message
                    error = u'{}'.format(e)

            raise APIError(error)
        elif data.status_code == 403:
            raise APIError('Access denied (403 Forbidden)')

        # Parse the text into JSON
        try:
            data = data.json()
        except ValueError:
            raise APIError('Unable to parse JSON response')

        # Raise an exception if an error occurred
        if type(data) == dict and 'error' in data:
            raise APIError(data['error'])

        # Return the data
        return data

    def count(self, query, facets=None):
        """Returns the total number of search results for the query.

        :param query: Search query; identical syntax to the website
        :type query: str
        :param facets: (optional) A list of properties to get summary information on
        :type facets: str

        :returns: A dictionary with 1 main property: total. If facets have been provided then another property called "facets" will be available at the top-level of the dictionary. Visit the website for more detailed information.
        """
        query_args = {
            'query': query,
        }
        if facets:
            query_args['facets'] = create_facet_string(facets)
        return self._request('/shodan/host/count', query_args)

    def host(self, ips, history=False, minify=False):
        """Get all available information on an IP.

        :param ip: IP of the computer
        :type ip: str
        :param history: (optional) True if you want to grab the historical (non-current) banners for the host, False otherwise.
        :type history: bool
        :param minify: (optional) True to only return the list of ports and the general host information, no banners, False otherwise.
        :type minify: bool
        """
        if isinstance(ips, basestring):
            ips = [ips]

        params = {}
        if history:
            params['history'] = history
        if minify:
            params['minify'] = minify
        return self._request('/shodan/host/%s' % ','.join(ips), params)

    def info(self):
        """Returns information about the current API key, such as a list of add-ons
        and other features that are enabled for the current user's API plan.
        """
        return self._request('/api-info', {})

    def ports(self):
        """Get a list of ports that Shodan crawls

        :returns: An array containing the ports that Shodan crawls for.
        """
        return self._request('/shodan/ports', {})

    def protocols(self):
        """Get a list of protocols that the Shodan on-demand scanning API supports.

        :returns: A dictionary containing the protocol name and description.
        """
        return self._request('/shodan/protocols', {})

    def scan(self, ips, force=False):
        """Scan a network using Shodan

        :param ips: A list of IPs or netblocks in CIDR notation or an object structured like:
                    {
                        "9.9.9.9": [
                            (443, "https"),
                            (8080, "http")
                        ],
                        "1.1.1.0/24": [
                            (503, "modbus")
                        ]
                    }
        :type ips: str or dict
        :param force: Whether or not to force Shodan to re-scan the provided IPs. Only available to enterprise users.
        :type force: bool

        :returns: A dictionary with a unique ID to check on the scan progress, the number of IPs that will be crawled and how many scan credits are left.
        """
        if isinstance(ips, basestring):
            ips = [ips]

        if isinstance(ips, dict):
            networks = json.dumps(ips)
        else:
            networks = ','.join(ips)

        params = {
            'ips': networks,
            'force': force,
        }

        return self._request('/shodan/scan', params, method='post')

    def scans(self, page=1):
        """Get a list of scans submitted

        :param page: Page through the list of scans 100 results at a time
        :type page: int
        """
        return self._request('/shodan/scans', {
            'page': page,
        })

    def scan_internet(self, port, protocol):
        """Scan a network using Shodan

        :param port: The port that should get scanned.
        :type port: int
        :param port: The name of the protocol as returned by the protocols() method.
        :type port: str

        :returns: A dictionary with a unique ID to check on the scan progress.
        """
        params = {
            'port': port,
            'protocol': protocol,
        }

        return self._request('/shodan/scan/internet', params, method='post')

    def scan_status(self, scan_id):
        """Get the status information about a previously submitted scan.

        :param id: The unique ID for the scan that was submitted
        :type id: str

        :returns: A dictionary with general information about the scan, including its status in getting processed.
        """
        return self._request('/shodan/scan/%s' % scan_id, {})

    def search(self, query, page=1, limit=None, offset=None, facets=None, minify=True):
        """Search the SHODAN database.

        :param query: Search query; identical syntax to the website
        :type query: str
        :param page: (optional) Page number of the search results
        :type page: int
        :param limit: (optional) Number of results to return
        :type limit: int
        :param offset: (optional) Search offset to begin getting results from
        :type offset: int
        :param facets: (optional) A list of properties to get summary information on
        :type facets: str
        :param minify: (optional) Whether to minify the banner and only return the important data
        :type minify: bool

        :returns: A dictionary with 2 main items: matches and total. If facets have been provided then another property called "facets" will be available at the top-level of the dictionary. Visit the website for more detailed information.
        """
        args = {
            'query': query,
            'minify': minify,
        }
        if limit:
            args['limit'] = limit
            if offset:
                args['offset'] = offset
        else:
            args['page'] = page

        if facets:
            args['facets'] = create_facet_string(facets)

        return self._request('/shodan/host/search', args)

    def search_cursor(self, query, minify=True, retries=5):
        """Search the SHODAN database.

        This method returns an iterator that can directly be in a loop. Use it when you want to loop over
        all of the results of a search query. But this method doesn't return a "matches" array or the "total"
        information. And it also can't be used with facets, it's only use is to iterate over results more
        easily.

        :param query: Search query; identical syntax to the website
        :type query: str
        :param minify: (optional) Whether to minify the banner and only return the important data
        :type minify: bool
        :param retries: (optional) How often to retry the search in case it times out
        :type retries: int

        :returns: A search cursor that can be used as an iterator/ generator.
        """
        page = 1
        tries = 0

        # Placeholder results object to make the while loop below easier
        results = {
            'matches': [True],
            'total': None,
        }

        while results['matches']:
            try:
                results = self.search(query, minify=minify, page=page)
                for banner in results['matches']:
                    try:
                        yield banner
                    except GeneratorExit:
                        return  # exit out of the function
                page += 1
                tries = 0
            except Exception:
                # We've retried several times but it keeps failing, so lets error out
                if tries >= retries:
                    raise APIError('Retry limit reached ({:d})'.format(retries))

                tries += 1
                time.sleep(1.0)  # wait 1 second if the search errored out for some reason

    def search_facets(self):
        """Returns a list of search facets that can be used to get aggregate information about a search query.

        :returns: A list of strings where each is a facet name
        """
        return self._request('/shodan/host/search/facets', {})

    def search_filters(self):
        """Returns a list of search filters that are available.

        :returns: A list of strings where each is a filter name
        """
        return self._request('/shodan/host/search/filters', {})

    def search_tokens(self, query):
        """Returns information about the search query itself (filters used etc.)

        :param query: Search query; identical syntax to the website
        :type query: str

        :returns: A dictionary with 4 main properties: filters, errors, attributes and string.
        """
        query_args = {
            'query': query,
        }
        return self._request('/shodan/host/search/tokens', query_args)

    def services(self):
        """Get a list of services that Shodan crawls

        :returns: A dictionary containing the ports/ services that Shodan crawls for. The key is the port number and the value is the name of the service.
        """
        return self._request('/shodan/services', {})

    def queries(self, page=1, sort='timestamp', order='desc'):
        """List the search queries that have been shared by other users.

        :param page: Page number to iterate over results; each page contains 10 items
        :type page: int
        :param sort: Sort the list based on a property. Possible values are: votes, timestamp
        :type sort: str
        :param order: Whether to sort the list in ascending or descending order. Possible values are: asc, desc
        :type order: str

        :returns: A list of saved search queries (dictionaries).
        """
        args = {
            'page': page,
            'sort': sort,
            'order': order,
        }
        return self._request('/shodan/query', args)

    def queries_search(self, query, page=1):
        """Search the directory of saved search queries in Shodan.

        :param query: The search string to look for in the search query
        :type query: str
        :param page: Page number to iterate over results; each page contains 10 items
        :type page: int

        :returns: A list of saved search queries (dictionaries).
        """
        args = {
            'page': page,
            'query': query,
        }
        return self._request('/shodan/query/search', args)

    def queries_tags(self, size=10):
        """Search the directory of saved search queries in Shodan.

        :param size: The number of tags to return
        :type size: int

        :returns: A list of tags.
        """
        args = {
            'size': size,
        }
        return self._request('/shodan/query/tags', args)

    def create_alert(self, name, ip, expires=0):
        """Create a network alert/ private firehose for the specified IP range(s)

        :param name: Name of the alert
        :type name: str
        :param ip: Network range(s) to monitor
        :type ip: str OR list of str

        :returns: A dict describing the alert
        """
        data = {
            'name': name,
            'filters': {
                'ip': ip,
            },
            'expires': expires,
        }

        response = api_request(self.api_key, '/shodan/alert', data=data, params={}, method='post',
                               proxies=self._session.proxies)

        return response

    def edit_alert(self, aid, ip):
        """Edit the IPs that should be monitored by the alert.

        :param aid: Alert ID
        :type name: str
        :param ip: Network range(s) to monitor
        :type ip: str OR list of str

        :returns: A dict describing the alert
        """
        data = {
            'filters': {
                'ip': ip,
            },
        }

        response = api_request(self.api_key, '/shodan/alert/{}'.format(aid), data=data, params={}, method='post',
                               proxies=self._session.proxies)

        return response

    def alerts(self, aid=None, include_expired=True):
        """List all of the active alerts that the user created."""
        if aid:
            func = '/shodan/alert/%s/info' % aid
        else:
            func = '/shodan/alert/info'

        response = api_request(self.api_key, func, params={
            'include_expired': include_expired,
        }, proxies=self._session.proxies)

        return response

    def delete_alert(self, aid):
        """Delete the alert with the given ID."""
        func = '/shodan/alert/%s' % aid

        response = api_request(self.api_key, func, params={}, method='delete',
                               proxies=self._session.proxies)

        return response

    def alert_triggers(self):
        """Return a list of available triggers that can be enabled for alerts.

        :returns: A list of triggers
        """
        return self._request('/shodan/alert/triggers', {})

    def enable_alert_trigger(self, aid, trigger):
        """Enable the given trigger on the alert."""
        return self._request('/shodan/alert/{}/trigger/{}'.format(aid, trigger), {}, method='put')

    def disable_alert_trigger(self, aid, trigger):
        """Disable the given trigger on the alert."""
        return self._request('/shodan/alert/{}/trigger/{}'.format(aid, trigger), {}, method='delete')

    def ignore_alert_trigger_notification(self, aid, trigger, ip, port):
        """Ignore trigger notifications for the provided IP and port."""
        return self._request('/shodan/alert/{}/trigger/{}/ignore/{}:{}'.format(aid, trigger, ip, port), {}, method='put')

    def unignore_alert_trigger_notification(self, aid, trigger, ip, port):
        """Re-enable trigger notifications for the provided IP and port"""
        return self._request('/shodan/alert/{}/trigger/{}/ignore/{}:{}'.format(aid, trigger, ip, port), {}, method='delete')
    
    def add_alert_notifier(self, aid, nid):
        """Enable the given notifier for an alert that has triggers enabled."""
        return self._request('/shodan/alert/{}/notifier/{}'.format(aid, nid), {}, method='put')
    
    def remove_alert_notifier(self, aid, nid):
        """Remove the given notifier for an alert that has triggers enabled."""
        return self._request('/shodan/alert/{}/notifier/{}'.format(aid, nid), {}, method='delete')
