from thirdparty import requests
import json
import ssl

from .exception import APIError


class Stream:

    base_url = 'https://stream.shodan.io'

    def __init__(self, api_key, proxies=None):
        self.api_key = api_key
        self.proxies = proxies

    def _create_stream(self, name, timeout=None):
        params = {
            'key': self.api_key,
        }
        stream_url = self.base_url + name

        # The user doesn't want to use a timeout
        # If the timeout is specified as 0 then we also don't want to have a timeout
        if (timeout and timeout <= 0) or (timeout == 0):
            timeout = None

        # If the user requested a timeout then we need to disable heartbeat messages
        # which are intended to keep stream connections alive even if there isn't any data
        # flowing through.
        if timeout:
            params['heartbeat'] = False

        try:
            while True:
                req = requests.get(stream_url, params=params, stream=True, timeout=timeout,
                                   proxies=self.proxies)

                # Status code 524 is special to Cloudflare
                # It means that no data was sent from the streaming servers which caused Cloudflare
                # to terminate the connection.
                #
                # We only want to exit if there was a timeout specified or the HTTP status code is
                # not specific to Cloudflare.
                if req.status_code != 524 or timeout >= 0:
                    break
        except Exception:
            raise APIError('Unable to contact the Shodan Streaming API')

        if req.status_code != 200:
            try:
                data = json.loads(req.text)
                raise APIError(data['error'])
            except APIError:
                raise
            except Exception:
                pass
            raise APIError('Invalid API key or you do not have access to the Streaming API')
        if req.encoding is None:
            req.encoding = 'utf-8'
        return req

    def _iter_stream(self, stream, raw):
        for line in stream.iter_lines(decode_unicode=True):
            # The Streaming API sends out heartbeat messages that are newlines
            # We want to ignore those messages since they don't contain any data
            if line:
                if raw:
                    yield line
                else:
                    yield json.loads(line)

    def alert(self, aid=None, timeout=None, raw=False):
        if aid:
            stream = self._create_stream('/shodan/alert/%s' % aid, timeout=timeout)
        else:
            stream = self._create_stream('/shodan/alert', timeout=timeout)

        try:
            for line in self._iter_stream(stream, raw):
                yield line
        except requests.exceptions.ConnectionError:
            raise APIError('Stream timed out')
        except ssl.SSLError:
            raise APIError('Stream timed out')

    def asn(self, asn, raw=False, timeout=None):
        """
        A filtered version of the "banners" stream to only return banners that match the ASNs of interest.

        :param asn: A list of ASN to return banner data on.
        :type asn: string[]
        """
        stream = self._create_stream('/shodan/asn/%s' % ','.join(asn), timeout=timeout)
        for line in self._iter_stream(stream, raw):
            yield line

    def banners(self, raw=False, timeout=None):
        """A real-time feed of the data that Shodan is currently collecting. Note that this is only available to
        API subscription plans and for those it only returns a fraction of the data.
        """
        stream = self._create_stream('/shodan/banners', timeout=timeout)
        for line in self._iter_stream(stream, raw):
            yield line

    def countries(self, countries, raw=False, timeout=None):
        """
        A filtered version of the "banners" stream to only return banners that match the countries of interest.

        :param countries: A list of countries to return banner data on.
        :type countries: string[]
        """
        stream = self._create_stream('/shodan/countries/%s' % ','.join(countries), timeout=timeout)
        for line in self._iter_stream(stream, raw):
            yield line

    def ports(self, ports, raw=False, timeout=None):
        """
        A filtered version of the "banners" stream to only return banners that match the ports of interest.

        :param ports: A list of ports to return banner data on.
        :type ports: int[]
        """
        stream = self._create_stream('/shodan/ports/%s' % ','.join([str(port) for port in ports]), timeout=timeout)
        for line in self._iter_stream(stream, raw):
            yield line

    def tags(self, tags, raw=False, timeout=None):
        """
        A filtered version of the "banners" stream to only return banners that match the tags of interest.

        :param tags: A list of tags to return banner data on.
        :type tags: string[]
        """
        stream = self._create_stream('/shodan/tags/%s' % ','.join(tags), timeout=timeout)
        for line in self._iter_stream(stream, raw):
            yield line

    def vulns(self, vulns, raw=False, timeout=None):
        """
        A filtered version of the "banners" stream to only return banners that match the vulnerabilities of interest.

        :param vulns: A list of vulns to return banner data on.
        :type vulns: string[]
        """
        stream = self._create_stream('/shodan/vulns/%s' % ','.join(vulns), timeout=timeout)
        for line in self._iter_stream(stream, raw):
            yield line
