'''
Helper methods used across the CLI commands.
'''
import click
import datetime
import gzip
import itertools
import os
import sys
from thirdparty.ipaddress.ipaddress import ip_network, ip_address

from .settings import SHODAN_CONFIG_DIR

try:
    basestring            # Python 2
except NameError:
    basestring = (str, )  # Python 3


def get_api_key():
    '''Returns the API key of the current logged-in user.'''
    shodan_dir = os.path.expanduser(SHODAN_CONFIG_DIR)
    keyfile = shodan_dir + '/api_key'

    # If the file doesn't yet exist let the user know that they need to
    # initialize the shodan cli
    if not os.path.exists(keyfile):
        raise click.ClickException('Please run "shodan init <api key>" before using this command')

    # Make sure it is a read-only file
    if not oct(os.stat(keyfile).st_mode).endswith("600"):
        os.chmod(keyfile, 0o600)

    with open(keyfile, 'r') as fin:
        return fin.read().strip()


def escape_data(args):
    # Make sure the string is unicode so the terminal can properly display it
    # We do it using format() so it works across Python 2 and 3
    args = u'{}'.format(args)
    return args.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')


def timestr():
    return datetime.datetime.utcnow().strftime('%Y-%m-%d')


def open_streaming_file(directory, timestr, compresslevel=9):
    return gzip.open('%s/%s.json.gz' % (directory, timestr), 'a', compresslevel)


def get_banner_field(banner, flat_field):
    # The provided field is a collapsed form of the actual field
    fields = flat_field.split('.')

    try:
        current_obj = banner
        for field in fields:
            current_obj = current_obj[field]
        return current_obj
    except Exception:
        pass

    return None


def filter_with_netmask(banner, netmask):
    # filtering based on netmask is a more abstract concept than
    # a mere check for a specific field and thus needs its own mechanism
    # this will enable users to use the net:10.0.0.0/8 syntax they are used to
    # to find specific networks from a big shodan download.
    network = ip_network(netmask)
    ip_field = get_banner_field(banner, 'ip')
    if not ip_field:
        return False
    banner_ip_address = ip_address(ip_field)
    return banner_ip_address in network


def match_filters(banner, filters):
    for args in filters:
        flat_field, check = args.split(':', 1)
        if flat_field == 'net':
            return filter_with_netmask(banner, check)

        value = get_banner_field(banner, flat_field)

        # If the field doesn't exist on the banner then ignore the record
        if not value:
            return False

        # It must match all filters to be allowed
        field_type = type(value)

        # For lists of strings we see whether the desired value is contained in the field
        if field_type == list or isinstance(value, basestring):
            if check not in value:
                return False
        elif field_type == int:
            if int(check) != value:
                return False
        elif field_type == float:
            if float(check) != value:
                return False
        else:
            # Ignore unknown types
            pass

    return True


def async_spinner(finished):
    spinner = itertools.cycle(['-', '/', '|', '\\'])
    while not finished.is_set():
        sys.stdout.write('\b{}'.format(next(spinner)))
        sys.stdout.flush()
        finished.wait(0.2)


def humanize_api_plan(plan):
    return {
        'oss': 'Free',
        'dev': 'Membership',
        'basic': 'Freelancer API',
        'plus': 'Small Business API',
        'corp': 'Corporate API',
        'stream-100': 'Enterprise',
    }[plan]
