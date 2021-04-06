"""
Shodan CLI

Note: Always run "shodan init <api key>" before trying to execute any other command!

A simple interface to search Shodan, download data and parse compressed JSON files.
The following commands are currently supported:

    alert
    convert
    count
    data
    download
    honeyscore
    host
    info
    init
    myip
    parse
    radar
    scan
    search
    stats
    stream

"""

from thirdparty import click
import csv
import os
import os.path
import pkg_resources
from thirdparty import shodan
import thirdparty.shodan.helpers as helpers
import threading
from thirdparty import requests
import time

# The file converters that are used to go from .json.gz to various other formats
from thirdparty.shodan.cli.converter import CsvConverter, KmlConverter, GeoJsonConverter, ExcelConverter, ImagesConverter

# Constants
from thirdparty.shodan.cli.settings import SHODAN_CONFIG_DIR, COLORIZE_FIELDS

# Helper methods
from thirdparty.shodan.cli.helpers import async_spinner, get_api_key, escape_data, timestr, open_streaming_file, get_banner_field, match_filters
from thirdparty.shodan.cli.host import HOST_PRINT

# Allow 3rd-parties to develop custom commands
from thirdparty.click_plugins.core import with_plugins
from pkg_resources import iter_entry_points

# Large subcommands are stored in separate modules
from thirdparty.shodan.cli.alert import alert
from thirdparty.shodan.cli.data import data
from thirdparty.shodan.cli.organization import org
from thirdparty.shodan.cli.scan import scan


# Make "-h" work like "--help"
CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])
CONVERTERS = {
    'kml': KmlConverter,
    'csv': CsvConverter,
    'geo.json': GeoJsonConverter,
    'images': ImagesConverter,
    'xlsx': ExcelConverter,
}

# Define a basestring type if necessary for Python3 compatibility
try:
    basestring
except NameError:
    basestring = str


# Define the main entry point for all of our commands
# and expose a way for 3rd-party plugins to tie into the Shodan CLI.
@with_plugins(iter_entry_points('shodan.cli.plugins'))
@click.group(context_settings=CONTEXT_SETTINGS)
def main():
    pass


# Setup the large subcommands
main.add_command(alert)
main.add_command(data)
main.add_command(org)
main.add_command(scan)


@main.command()
@click.option('--fields', help='List of properties to output.', default=None)
@click.argument('input', metavar='<input file>')
@click.argument('format', metavar='<output format>', type=click.Choice(CONVERTERS.keys()))
def convert(fields, input, format):
    """Convert the given input data file into a different format. The following file formats are supported:

    kml, csv, geo.json, images, xlsx

    Example: shodan convert data.json.gz kml
    """
    # Check that the converter allows a custom list of fields
    converter_class = CONVERTERS.get(format)
    if fields:
        if not hasattr(converter_class, 'fields'):
            raise click.ClickException('File format doesnt support custom list of fields')
        converter_class.fields = [item.strip() for item in fields.split(',')]  # Use the custom fields the user specified
    
    # Get the basename for the input file
    basename = input.replace('.json.gz', '').replace('.json', '')

    # Add the new file extension based on the format
    filename = '{}.{}'.format(basename, format)

    # Open the output file
    fout = open(filename, 'w')

    # Start a spinner
    finished_event = threading.Event()
    progress_bar_thread = threading.Thread(target=async_spinner, args=(finished_event,))
    progress_bar_thread.start()

    # Initialize the file converter
    converter = converter_class(fout)

    converter.process([input])

    finished_event.set()
    progress_bar_thread.join()

    if format == 'images':
        click.echo(click.style('\rSuccessfully extracted images to directory: {}'.format(converter.dirname), fg='green'))
    else:
        click.echo(click.style('\rSuccessfully created new file: {}'.format(filename), fg='green'))


@main.command(name='domain')
@click.argument('domain', metavar='<domain>')
@click.option('--details', '-D', help='Lookup host information for any IPs in the domain results', default=False, is_flag=True)
@click.option('--save', '-S', help='Save the information in the a file named after the domain (append if file exists).', default=False, is_flag=True)
@click.option('--history', '-H', help='Include historical DNS data in the results', default=False, is_flag=True)
@click.option('--type', '-T', help='Only returns DNS records of the provided type', default=None)
def domain_info(domain, details, save, history, type):
    """View all available information for a domain"""
    key = get_api_key()
    api = shodan.Shodan(key)

    try:
        info = api.dns.domain_info(domain, history=history, type=type)
    except shodan.APIError as e:
        raise click.ClickException(e.value)

    # Grab the host information for any IP records that were returned
    hosts = {}
    if details:
        ips = [record['value'] for record in info['data'] if record['type'] in ['A', 'AAAA']]
        ips = set(ips)

        fout = None
        if save:
            filename = u'{}-hosts.json.gz'.format(domain)
            fout = helpers.open_file(filename)

        for ip in ips:
            try:
                hosts[ip] = api.host(ip)

                # Store the banners if requested
                if fout:
                    for banner in hosts[ip]['data']:
                        if 'placeholder' not in banner:
                            helpers.write_banner(fout, banner)
            except shodan.APIError:
                pass  # Ignore any API lookup errors as this isn't critical information
    
    # Save the DNS data
    if save:
        filename = u'{}.json.gz'.format(domain)
        fout = helpers.open_file(filename)

        for record in info['data']:
            helpers.write_banner(fout, record)

    click.secho(info['domain'].upper(), fg='green')

    click.echo('')
    for record in info['data']:
        click.echo(
            u'{:32}  {:14}  {}'.format(
                click.style(record['subdomain'], fg='cyan'),
                click.style(record['type'], fg='yellow'),
                record['value']
            ),
            nl=False,
        )

        if record['value'] in hosts:
            host = hosts[record['value']]
            click.secho(u' Ports: {}'.format(', '.join([str(port) for port in sorted(host['ports'])])), fg='blue', nl=False)
        
        click.echo('')


@main.command()
@click.argument('key', metavar='<api key>')
def init(key):
    """Initialize the Shodan command-line"""
    # Create the directory if necessary
    shodan_dir = os.path.expanduser(SHODAN_CONFIG_DIR)
    if not os.path.isdir(shodan_dir):
        try:
            os.makedirs(shodan_dir)
        except OSError:
            raise click.ClickException('Unable to create directory to store the Shodan API key ({})'.format(shodan_dir))

    # Make sure it's a valid API key
    key = key.strip()
    try:
        api = shodan.Shodan(key)
        api.info()
    except shodan.APIError as e:
        raise click.ClickException(e.value)

    # Store the API key in the user's directory
    keyfile = shodan_dir + '/api_key'
    with open(keyfile, 'w') as fout:
        fout.write(key.strip())
        click.echo(click.style('Successfully initialized', fg='green'))

    os.chmod(keyfile, 0o600)


@main.command()
@click.argument('query', metavar='<search query>', nargs=-1)
def count(query):
    """Returns the number of results for a search"""
    key = get_api_key()

    # Create the query string out of the provided tuple
    query = ' '.join(query).strip()

    # Make sure the user didn't supply an empty string
    if query == '':
        raise click.ClickException('Empty search query')

    # Perform the search
    api = shodan.Shodan(key)
    try:
        results = api.count(query)
    except shodan.APIError as e:
        raise click.ClickException(e.value)

    click.echo(results['total'])


@main.command()
@click.option('--limit', help='The number of results you want to download. -1 to download all the data possible.', default=1000, type=int)
@click.argument('filename', metavar='<filename>')
@click.argument('query', metavar='<search query>', nargs=-1)
def download(limit, filename, query):
    """Download search results and save them in a compressed JSON file."""
    key = get_api_key()

    # Create the query string out of the provided tuple
    query = ' '.join(query).strip()

    # Make sure the user didn't supply an empty string
    if query == '':
        raise click.ClickException('Empty search query')

    filename = filename.strip()
    if filename == '':
        raise click.ClickException('Empty filename')

    # Add the appropriate extension if it's not there atm
    if not filename.endswith('.json.gz'):
        filename += '.json.gz'

    # Perform the search
    api = shodan.Shodan(key)

    try:
        total = api.count(query)['total']
        info = api.info()
    except Exception:
        raise click.ClickException('The Shodan API is unresponsive at the moment, please try again later.')

    # Print some summary information about the download request
    click.echo('Search query:\t\t\t%s' % query)
    click.echo('Total number of results:\t%s' % total)
    click.echo('Query credits left:\t\t%s' % info['unlocked_left'])
    click.echo('Output file:\t\t\t%s' % filename)

    if limit > total:
        limit = total

    # A limit of -1 means that we should download all the data
    if limit <= 0:
        limit = total

    with helpers.open_file(filename, 'w') as fout:
        count = 0
        try:
            cursor = api.search_cursor(query, minify=False)
            with click.progressbar(cursor, length=limit) as bar:
                for banner in bar:
                    helpers.write_banner(fout, banner)
                    count += 1

                    if count >= limit:
                        break
        except Exception:
            pass

        # Let the user know we're done
        if count < limit:
            click.echo(click.style('Notice: fewer results were saved than requested', 'yellow'))
        click.echo(click.style(u'Saved {} results into file {}'.format(count, filename), 'green'))


@main.command()
@click.option('--format', help='The output format for the host information. Possible values are: pretty, tsv.', default='pretty', type=click.Choice(['pretty', 'tsv']))
@click.option('--history', help='Show the complete history of the host.', default=False, is_flag=True)
@click.option('--filename', '-O', help='Save the host information in the given file (append if file exists).', default=None)
@click.option('--save', '-S', help='Save the host information in the a file named after the IP (append if file exists).', default=False, is_flag=True)
@click.argument('ip', metavar='<ip address>')
def host(format, history, filename, save, ip):
    """View all available information for an IP address"""
    key = get_api_key()
    api = shodan.Shodan(key)

    try:
        host = api.host(ip, history=history)

        # Print the host information to the terminal using the user-specified format
        HOST_PRINT[format](host, history=history)

        # Store the results
        if filename or save:
            if save:
                filename = '{}.json.gz'.format(ip)

            # Add the appropriate extension if it's not there atm
            if not filename.endswith('.json.gz'):
                filename += '.json.gz'

            # Create/ append to the file
            fout = helpers.open_file(filename)

            for banner in sorted(host['data'], key=lambda k: k['port']):
                if 'placeholder' not in banner:
                    helpers.write_banner(fout, banner)
    except shodan.APIError as e:
        raise click.ClickException(e.value)


@main.command()
def info():
    """Shows general information about your account"""
    key = get_api_key()
    api = shodan.Shodan(key)
    try:
        results = api.info()
    except shodan.APIError as e:
        raise click.ClickException(e.value)

    click.echo("""Query credits available: {0}
Scan credits available: {1}
    """.format(results['query_credits'], results['scan_credits']))


@main.command()
@click.option('--color/--no-color', default=True)
@click.option('--fields', help='List of properties to output.', default='ip_str,port,hostnames,data')
@click.option('--filters', '-f', help='Filter the results for specific values using key:value pairs.', multiple=True)
@click.option('--filename', '-O', help='Save the filtered results in the given file (append if file exists).')
@click.option('--separator', help='The separator between the properties of the search results.', default=u'\t')
@click.argument('filenames', metavar='<filenames>', type=click.Path(exists=True), nargs=-1)
def parse(color, fields, filters, filename, separator, filenames):
    """Extract information out of compressed JSON files."""
    # Strip out any whitespace in the fields and turn them into an array
    fields = [item.strip() for item in fields.split(',')]

    if len(fields) == 0:
        raise click.ClickException('Please define at least one property to show')

    has_filters = len(filters) > 0

    # Setup the output file handle
    fout = None
    if filename:
        # If no filters were provided raise an error since it doesn't make much sense w/out them
        if not has_filters:
            raise click.ClickException('Output file specified without any filters. Need to use filters with this option.')

        # Add the appropriate extension if it's not there atm
        if not filename.endswith('.json.gz'):
            filename += '.json.gz'
        fout = helpers.open_file(filename)

    for banner in helpers.iterate_files(filenames):
        row = u''

        # Validate the banner against any provided filters
        if has_filters and not match_filters(banner, filters):
            continue

        # Append the data
        if fout:
            helpers.write_banner(fout, banner)

        # Loop over all the fields and print the banner as a row
        for i, field in enumerate(fields):
            tmp = u''
            value = get_banner_field(banner, field)
            if value:
                field_type = type(value)

                # If the field is an array then merge it together
                if field_type == list:
                    tmp = u';'.join(value)
                elif field_type in [int, float]:
                    tmp = u'{}'.format(value)
                else:
                    tmp = escape_data(value)

                # Colorize certain fields if the user wants it
                if color:
                    tmp = click.style(tmp, fg=COLORIZE_FIELDS.get(field, 'white'))

            # Add the field information to the row
            if i > 0:
                row += separator
            row += tmp

        click.echo(row)


@main.command()
@click.option('--ipv6', '-6', is_flag=True, default=False, help='Try to use IPv6 instead of IPv4')
def myip(ipv6):
    """Print your external IP address"""
    key = get_api_key()

    api = shodan.Shodan(key)

    # Use the IPv6-enabled domain if requested
    if ipv6:
        api.base_url = 'https://apiv6.shodan.io'
    
    try:
        click.echo(api.tools.myip())
    except shodan.APIError as e:
        raise click.ClickException(e.value)


@main.command()
@click.option('--color/--no-color', default=True)
@click.option('--fields', help='List of properties to show in the search results.', default='ip_str,port,hostnames,data')
@click.option('--limit', help='The number of search results that should be returned. Maximum: 1000', default=100, type=int)
@click.option('--separator', help='The separator between the properties of the search results.', default='\t')
@click.argument('query', metavar='<search query>', nargs=-1)
def search(color, fields, limit, separator, query):
    """Search the Shodan database"""
    key = get_api_key()

    # Create the query string out of the provided tuple
    query = ' '.join(query).strip()

    # Make sure the user didn't supply an empty string
    if query == '':
        raise click.ClickException('Empty search query')

    # For now we only allow up to 1000 results at a time
    if limit > 1000:
        raise click.ClickException('Too many results requested, maximum is 1,000')

    # Strip out any whitespace in the fields and turn them into an array
    fields = [item.strip() for item in fields.split(',')]

    if len(fields) == 0:
        raise click.ClickException('Please define at least one property to show')

    # Perform the search
    api = shodan.Shodan(key)
    try:
        results = api.search(query, limit=limit)
    except shodan.APIError as e:
        raise click.ClickException(e.value)

    # Error out if no results were found
    if results['total'] == 0:
        raise click.ClickException('No search results found')

    # We buffer the entire output so we can use click's pager functionality
    output = u''
    for banner in results['matches']:
        row = u''

        # Loop over all the fields and print the banner as a row
        for field in fields:
            tmp = u''
            value = get_banner_field(banner, field)
            if value:
                field_type = type(value)

                # If the field is an array then merge it together
                if field_type == list:
                    tmp = u';'.join(value)
                elif field_type in [int, float]:
                    tmp = u'{}'.format(value)
                else:
                    tmp = escape_data(value)

                # Colorize certain fields if the user wants it
                if color:
                    tmp = click.style(tmp, fg=COLORIZE_FIELDS.get(field, 'white'))

                # Add the field information to the row
                row += tmp
            row += separator

            # click.echo(out + separator, nl=False)
        output += row + u'\n'
        # click.echo('')
    click.echo_via_pager(output)


@main.command()
@click.option('--limit', help='The number of results to return.', default=10, type=int)
@click.option('--facets', help='List of facets to get statistics for.', default='country,org')
@click.option('--filename', '-O', help='Save the results in a CSV file of the provided name.', default=None)
@click.argument('query', metavar='<search query>', nargs=-1)
def stats(limit, facets, filename, query):
    """Provide summary information about a search query"""
    # Setup Shodan
    key = get_api_key()
    api = shodan.Shodan(key)

    # Create the query string out of the provided tuple
    query = ' '.join(query).strip()

    # Make sure the user didn't supply an empty string
    if query == '':
        raise click.ClickException('Empty search query')

    facets = facets.split(',')
    facets = [(facet, limit) for facet in facets]

    # Perform the search
    try:
        results = api.count(query, facets=facets)
    except shodan.APIError as e:
        raise click.ClickException(e.value)

    # Print the stats tables
    for facet in results['facets']:
        click.echo('Top {} Results for Facet: {}'.format(len(results['facets'][facet]), facet))

        for item in results['facets'][facet]:
            # Force the value to be a string - necessary because some facet values are numbers
            value = u'{}'.format(item['value'])

            click.echo(click.style(u'{:28s}'.format(value), fg='cyan'), nl=False)
            click.echo(click.style(u'{:12,d}'.format(item['count']), fg='green'))

        click.echo('')

    # Create the output file if requested
    fout = None
    if filename:
        if not filename.endswith('.csv'):
            filename += '.csv'
        fout = open(filename, 'w')
        writer = csv.writer(fout, dialect=csv.excel)

        # Write the header
        writer.writerow(['Query', query])

        # Add an empty line to separate rows
        writer.writerow([])

        # Write the header that contains the facets
        row = []
        for facet in results['facets']:
            row.append(facet)
            row.append('')
        writer.writerow(row)

        # Every facet has 2 columns (key, value)
        counter = 0
        has_items = True
        while has_items:
            # pylint: disable=W0612
            row = ['' for i in range(len(results['facets']) * 2)]

            pos = 0
            has_items = False
            for facet in results['facets']:
                values = results['facets'][facet]

                # Add the values for the facet into the current row
                if len(values) > counter:
                    has_items = True
                    row[pos] = values[counter]['value']
                    row[pos + 1] = values[counter]['count']

                pos += 2

            # Write out the row
            if has_items:
                writer.writerow(row)

            # Move to the next row of values
            counter += 1


@main.command()
@click.option('--color/--no-color', default=True)
@click.option('--fields', help='List of properties to output.', default='ip_str,port,hostnames,data')
@click.option('--separator', help='The separator between the properties of the search results.', default='\t')
@click.option('--limit', help='The number of results you want to download. -1 to download all the data possible.', default=-1, type=int)
@click.option('--datadir', help='Save the stream data into the specified directory as .json.gz files.', default=None, type=str)
@click.option('--ports', help='A comma-separated list of ports to grab data on.', default=None, type=str)
@click.option('--quiet', help='Disable the printing of information to the screen.', is_flag=True)
@click.option('--timeout', help='Timeout. Should the shodan stream cease to send data, then timeout after <timeout> seconds.', default=0, type=int)
@click.option('--streamer', help='Specify a custom Shodan stream server to use for grabbing data.', default='https://stream.shodan.io', type=str)
@click.option('--countries', help='A comma-separated list of countries to grab data on.', default=None, type=str)
@click.option('--asn', help='A comma-separated list of ASNs to grab data on.', default=None, type=str)
@click.option('--alert', help='The network alert ID or "all" to subscribe to all network alerts on your account.', default=None, type=str)
@click.option('--tags', help='A comma-separated list of tags to grab data on.', default=None, type=str)
@click.option('--compresslevel', help='The gzip compression level (0-9; 0 = no compression, 9 = most compression', default=9, type=int)
@click.option('--vulns', help='A comma-separated list of vulnerabilities to grab data on.', default=None, type=str)
def stream(color, fields, separator, limit, datadir, ports, quiet, timeout, streamer, countries, asn, alert, tags, compresslevel, vulns):
    """Stream data in real-time."""
    # Setup the Shodan API
    key = get_api_key()
    api = shodan.Shodan(key)

    # Temporarily change the baseurl
    api.stream.base_url = streamer

    # Strip out any whitespace in the fields and turn them into an array
    fields = [item.strip() for item in fields.split(',')]

    if len(fields) == 0:
        raise click.ClickException('Please define at least one property to show')

    # The user must choose "ports", "countries", "asn" or nothing - can't select multiple
    # filtered streams at once.
    stream_type = []
    if ports:
        stream_type.append('ports')
    if countries:
        stream_type.append('countries')
    if asn:
        stream_type.append('asn')
    if alert:
        stream_type.append('alert')
    if tags:
        stream_type.append('tags')
    if vulns:
        stream_type.append('vulns')

    if len(stream_type) > 1:
        raise click.ClickException('Please use --ports, --countries, --tags, --vulns OR --asn. You cant subscribe to multiple filtered streams at once.')

    stream_args = None

    # Turn the list of ports into integers
    if ports:
        try:
            stream_args = [int(item.strip()) for item in ports.split(',')]
        except ValueError:
            raise click.ClickException('Invalid list of ports')

    if alert:
        alert = alert.strip()
        if alert.lower() != 'all':
            stream_args = alert

    if asn:
        stream_args = asn.split(',')

    if countries:
        stream_args = countries.split(',')
    
    if tags:
        stream_args = tags.split(',')
    
    if vulns:
        stream_args = vulns.split(',')

    # Flatten the list of stream types
    # Possible values are:
    # - all
    # - asn
    # - countries
    # - ports
    if len(stream_type) == 1:
        stream_type = stream_type[0]
    else:
        stream_type = 'all'

    # Decide which stream to subscribe to based on whether or not ports were selected
    def _create_stream(name, args, timeout):
        return {
            'all': api.stream.banners(timeout=timeout),
            'alert': api.stream.alert(args, timeout=timeout),
            'asn': api.stream.asn(args, timeout=timeout),
            'countries': api.stream.countries(args, timeout=timeout),
            'ports': api.stream.ports(args, timeout=timeout),
            'tags': api.stream.tags(args, timeout=timeout),
            'vulns': api.stream.vulns(args, timeout=timeout),
        }.get(name, 'all')

    stream = _create_stream(stream_type, stream_args, timeout=timeout)

    counter = 0
    quit = False
    last_time = timestr()
    fout = None

    if datadir:
        fout = open_streaming_file(datadir, last_time, compresslevel)

    while not quit:
        try:
            for banner in stream:
                # Limit the number of results to output
                if limit > 0:
                    counter += 1

                    if counter > limit:
                        quit = True
                        break

                # Write the data to the file
                if datadir:
                    cur_time = timestr()
                    if cur_time != last_time:
                        last_time = cur_time
                        fout.close()
                        fout = open_streaming_file(datadir, last_time)
                    helpers.write_banner(fout, banner)

                # Print the banner information to stdout
                if not quiet:
                    row = u''

                    # Loop over all the fields and print the banner as a row
                    for field in fields:
                        tmp = u''
                        value = get_banner_field(banner, field)
                        if value:
                            field_type = type(value)

                            # If the field is an array then merge it together
                            if field_type == list:
                                tmp = u';'.join(value)
                            elif field_type in [int, float]:
                                tmp = u'{}'.format(value)
                            else:
                                tmp = escape_data(value)

                            # Colorize certain fields if the user wants it
                            if color:
                                tmp = click.style(tmp, fg=COLORIZE_FIELDS.get(field, 'white'))

                            # Add the field information to the row
                            row += tmp
                        row += separator

                    click.echo(row)
        except requests.exceptions.Timeout:
            raise click.ClickException('Connection timed out')
        except KeyboardInterrupt:
            quit = True
        except shodan.APIError as e:
            raise click.ClickException(e.value)
        except Exception:
            # For other errors lets just wait a bit and try to reconnect again
            time.sleep(1)

            # Create a new stream object to subscribe to
            stream = _create_stream(stream_type, stream_args, timeout=timeout)


@main.command()
@click.argument('ip', metavar='<IP address>')
def honeyscore(ip):
    """Check whether the IP is a honeypot or not."""
    key = get_api_key()
    api = shodan.Shodan(key)

    try:
        score = api.labs.honeyscore(ip)

        if score == 1.0:
            click.echo(click.style('Honeypot detected', fg='red'))
        elif score > 0.5:
            click.echo(click.style('Probably a honeypot', fg='yellow'))
        else:
            click.echo(click.style('Not a honeypot', fg='green'))

        click.echo('Score: {}'.format(score))
    except Exception:
        raise click.ClickException('Unable to calculate honeyscore')


@main.command()
def radar():
    """Real-Time Map of some results as Shodan finds them."""
    key = get_api_key()
    api = shodan.Shodan(key)

    from thirdparty.shodan.cli.worldmap import launch_map

    try:
        launch_map(api)
    except shodan.APIError as e:
        raise click.ClickException(e.value)
    except Exception as e:
        raise click.ClickException(u'{}'.format(e))


@main.command()
def version():
    """Print version of this tool."""
    print(pkg_resources.get_distribution("shodan").version)


if __name__ == '__main__':
    main()
