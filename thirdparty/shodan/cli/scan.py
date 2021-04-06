import click
import collections
import datetime
from thirdparty import shodan
import thirdparty.shodan.helpers as helpers
import socket
import threading
import time

from thirdparty.shodan.cli.helpers import get_api_key, async_spinner
from thirdparty.shodan.cli.settings import COLORIZE_FIELDS


@click.group()
def scan():
    """Scan an IP/ netblock using Shodan."""
    pass


@scan.command(name='list')
def scan_list():
    """Show recently launched scans"""
    key = get_api_key()

    # Get the list
    api = shodan.Shodan(key)
    try:
        scans = api.scans()
    except shodan.APIError as e:
        raise click.ClickException(e.value)

    if len(scans) > 0:
        click.echo(u'# {} Scans Total - Showing 10 most recent scans:'.format(scans['total']))
        click.echo(u'# {:20} {:<15} {:<10} {:<15s}'.format('Scan ID', 'Status', 'Size', 'Timestamp'))
        # click.echo('#' * 65)
        for scan in scans['matches'][:10]:
            click.echo(
                u'{:31} {:<24} {:<10} {:<15s}'.format(
                    click.style(scan['id'], fg='yellow'),
                    click.style(scan['status'], fg='cyan'),
                    scan['size'],
                    scan['created']
                )
            )
    else:
        click.echo("You haven't yet launched any scans.")


@scan.command(name='internet')
@click.option('--quiet', help='Disable the printing of information to the screen.', default=False, is_flag=True)
@click.argument('port', type=int)
@click.argument('protocol', type=str)
def scan_internet(quiet, port, protocol):
    """Scan the Internet for a specific port and protocol using the Shodan infrastructure."""
    key = get_api_key()
    api = shodan.Shodan(key)

    try:
        # Submit the request to Shodan
        click.echo('Submitting Internet scan to Shodan...', nl=False)
        scan = api.scan_internet(port, protocol)
        click.echo('Done')

        # If the requested port is part of the regular Shodan crawling, then
        # we don't know when the scan is done so lets return immediately and
        # let the user decide when to stop waiting for further results.
        official_ports = api.ports()
        if port in official_ports:
            click.echo('The requested port is already indexed by Shodan. A new scan for the port has been launched, please subscribe to the real-time stream for results.')
        else:
            # Create the output file
            filename = '{0}-{1}.json.gz'.format(port, protocol)
            counter = 0
            with helpers.open_file(filename, 'w') as fout:
                click.echo('Saving results to file: {0}'.format(filename))

                # Start listening for results
                done = False

                # Keep listening for results until the scan is done
                click.echo('Waiting for data, please stand by...')
                while not done:
                    try:
                        for banner in api.stream.ports([port], timeout=90):
                            counter += 1
                            helpers.write_banner(fout, banner)

                            if not quiet:
                                click.echo('{0:<40} {1:<20} {2}'.format(
                                    click.style(helpers.get_ip(banner), fg=COLORIZE_FIELDS['ip_str']),
                                    click.style(str(banner['port']), fg=COLORIZE_FIELDS['port']),
                                    ';'.join(banner['hostnames']))
                                )
                    except shodan.APIError:
                        # We stop waiting for results if the scan has been processed by the crawlers and
                        # there haven't been new results in a while
                        if done:
                            break

                        scan = api.scan_status(scan['id'])
                        if scan['status'] == 'DONE':
                            done = True
                    except socket.timeout:
                        # We stop waiting for results if the scan has been processed by the crawlers and
                        # there haven't been new results in a while
                        if done:
                            break

                        scan = api.scan_status(scan['id'])
                        if scan['status'] == 'DONE':
                            done = True
                    except Exception as e:
                        raise click.ClickException(repr(e))
            click.echo('Scan finished: {0} devices found'.format(counter))
    except shodan.APIError as e:
        raise click.ClickException(e.value)


@scan.command(name='protocols')
def scan_protocols():
    """List the protocols that you can scan with using Shodan."""
    key = get_api_key()
    api = shodan.Shodan(key)
    try:
        protocols = api.protocols()

        for name, description in iter(protocols.items()):
            click.echo(click.style('{0:<30}'.format(name), fg='cyan') + description)
    except shodan.APIError as e:
        raise click.ClickException(e.value)


@scan.command(name='submit')
@click.option('--wait', help='How long to wait for results to come back. If this is set to "0" or below return immediately.', default=20, type=int)
@click.option('--filename', help='Save the results in the given file.', default='', type=str)
@click.option('--force', default=False, is_flag=True)
@click.option('--verbose', default=False, is_flag=True)
@click.argument('netblocks', metavar='<ip address>', nargs=-1)
def scan_submit(wait, filename, force, verbose, netblocks):
    """Scan an IP/ netblock using Shodan."""
    key = get_api_key()
    api = shodan.Shodan(key)
    alert = None

    # Submit the IPs for scanning
    try:
        # Submit the scan
        scan = api.scan(netblocks, force=force)

        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')

        click.echo('')
        click.echo('Starting Shodan scan at {} - {} scan credits left'.format(now, scan['credits_left']))

        if verbose:
            click.echo('# Scan ID: {}'.format(scan['id']))

        # Return immediately
        if wait <= 0:
            click.echo('Exiting now, not waiting for results. Use the API or website to retrieve the results of the scan.')
        else:
            # Setup an alert to wait for responses
            alert = api.create_alert('Scan: {}'.format(', '.join(netblocks)), netblocks)

            # Create the output file if necessary
            filename = filename.strip()
            fout = None
            if filename != '':
                # Add the appropriate extension if it's not there atm
                if not filename.endswith('.json.gz'):
                    filename += '.json.gz'
                fout = helpers.open_file(filename, 'w')

            # Start a spinner
            finished_event = threading.Event()
            progress_bar_thread = threading.Thread(target=async_spinner, args=(finished_event,))
            progress_bar_thread.start()

            # Now wait a few seconds for items to get returned
            hosts = collections.defaultdict(dict)
            done = False
            scan_start = time.time()
            cache = {}
            while not done:
                try:
                    for banner in api.stream.alert(aid=alert['id'], timeout=wait):
                        ip = banner.get('ip', banner.get('ipv6', None))
                        if not ip:
                            continue

                        # Don't show duplicate banners
                        cache_key = '{}:{}'.format(ip, banner['port'])
                        if cache_key not in cache:
                            hosts[helpers.get_ip(banner)][banner['port']] = banner
                            cache[cache_key] = True

                        # If we've grabbed data for more than 60 seconds it might just be a busy network and we should move on
                        if time.time() - scan_start >= 60:
                            scan = api.scan_status(scan['id'])

                            if verbose:
                                click.echo('# Scan status: {}'.format(scan['status']))

                            if scan['status'] == 'DONE':
                                done = True
                                break

                except shodan.APIError:
                    # If the connection timed out before the timeout, that means the streaming server
                    # that the user tried to reach is down. In that case, lets wait briefly and try
                    # to connect again!
                    if (time.time() - scan_start) < wait:
                        time.sleep(0.5)
                        continue

                    # Exit if the scan was flagged as done somehow
                    if done:
                        break

                    scan = api.scan_status(scan['id'])
                    if scan['status'] == 'DONE':
                        done = True

                    if verbose:
                        click.echo('# Scan status: {}'.format(scan['status']))
                except socket.timeout:
                    # If the connection timed out before the timeout, that means the streaming server
                    # that the user tried to reach is down. In that case, lets wait a second and try
                    # to connect again!
                    if (time.time() - scan_start) < wait:
                        continue

                    done = True
                except Exception as e:
                    finished_event.set()
                    progress_bar_thread.join()
                    raise click.ClickException(repr(e))

            finished_event.set()
            progress_bar_thread.join()

            def print_field(name, value):
                click.echo('  {:25s}{}'.format(name, value))

            def print_banner(banner):
                click.echo('    {:20s}'.format(click.style(str(banner['port']), fg='green') + '/' + banner['transport']), nl=False)

                if 'product' in banner:
                    click.echo(banner['product'], nl=False)

                    if 'version' in banner:
                        click.echo(' ({})'.format(banner['version']), nl=False)

                click.echo('')

                # Show optional ssl info
                if 'ssl' in banner:
                    if 'versions' in banner['ssl']:
                        # Only print SSL versions if they were successfully tested
                        versions = [version for version in sorted(banner['ssl']['versions']) if not version.startswith('-')]
                        if len(versions) > 0:
                            click.echo('    |-- SSL Versions: {}'.format(', '.join(versions)))
                    if 'dhparams' in banner['ssl'] and banner['ssl']['dhparams']:
                        click.echo('    |-- Diffie-Hellman Parameters:')
                        click.echo('        {:15s}{}\n        {:15s}{}'.format('Bits:', banner['ssl']['dhparams']['bits'], 'Generator:', banner['ssl']['dhparams']['generator']))
                        if 'fingerprint' in banner['ssl']['dhparams']:
                            click.echo('        {:15s}{}'.format('Fingerprint:', banner['ssl']['dhparams']['fingerprint']))

            if hosts:
                # Remove the remaining spinner character
                click.echo('\b ')

                for ip in sorted(hosts):
                    host = next(iter(hosts[ip].items()))[1]

                    click.echo(click.style(ip, fg='cyan'), nl=False)
                    if 'hostnames' in host and host['hostnames']:
                        click.echo(' ({})'.format(', '.join(host['hostnames'])), nl=False)
                    click.echo('')

                    if 'location' in host and 'country_name' in host['location'] and host['location']['country_name']:
                        print_field('Country', host['location']['country_name'])

                        if 'city' in host['location'] and host['location']['city']:
                            print_field('City', host['location']['city'])
                    if 'org' in host and host['org']:
                        print_field('Organization', host['org'])
                    if 'os' in host and host['os']:
                        print_field('Operating System', host['os'])
                    click.echo('')

                    # Output the vulnerabilities the host has
                    if 'vulns' in host and len(host['vulns']) > 0:
                        vulns = []
                        for vuln in host['vulns']:
                            if vuln.startswith('!'):
                                continue
                            if vuln.upper() == 'CVE-2014-0160':
                                vulns.append(click.style('Heartbleed', fg='red'))
                            else:
                                vulns.append(click.style(vuln, fg='red'))

                        if len(vulns) > 0:
                            click.echo('  {:25s}'.format('Vulnerabilities:'), nl=False)

                            for vuln in vulns:
                                click.echo(vuln + '\t', nl=False)

                            click.echo('')

                    # Print all the open ports:
                    click.echo('  Open Ports:')
                    for port in sorted(hosts[ip]):
                        print_banner(hosts[ip][port])

                        # Save the banner in a file if necessary
                        if fout:
                            helpers.write_banner(fout, hosts[ip][port])

                    click.echo('')
            else:
                # Prepend a \b to remove the spinner
                click.echo('\bNo open ports found or the host has been recently crawled and cant get scanned again so soon.')
    except shodan.APIError as e:
        raise click.ClickException(e.value)
    finally:
        # Remove any alert
        if alert:
            api.delete_alert(alert['id'])


@scan.command(name='status')
@click.argument('scan_id', type=str)
def scan_status(scan_id):
    """Check the status of an on-demand scan."""
    key = get_api_key()
    api = shodan.Shodan(key)
    try:
        scan = api.scan_status(scan_id)
        click.echo(scan['status'])
    except shodan.APIError as e:
        raise click.ClickException(e.value)
