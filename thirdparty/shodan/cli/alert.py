import click
import csv
from thirdparty import shodan

from collections import defaultdict
from operator import itemgetter
from thirdparty.shodan import APIError
from thirdparty.shodan.cli.helpers import get_api_key
from thirdparty.shodan.helpers import open_file, write_banner
from time import sleep


MAX_QUERY_LENGTH = 1000


def aggregate_facet(api, networks, facets):
    """Merge the results from multiple facet API queries into a single result object.
    This is necessary because a user might be monitoring a lot of IPs/ networks so it doesn't fit
    into a single API call.
    """
    def _merge_custom_facets(lfacets, results):
        for key in results['facets']:
            if key not in lfacets:
                lfacets[key] = defaultdict(int)

            for item in results['facets'][key]:
                lfacets[key][item['value']] += item['count']

    # We're going to create a custom facets dict where
    # the key is the value of a facet. Normally the facets
    # object is a list where each item has a "value" and "count" property.
    tmp_facets = {}
    count = 0

    query = 'net:'

    for net in networks:
        query += '{},'.format(net)

        # Start running API queries if the query length is getting long
        if len(query) > MAX_QUERY_LENGTH:
            results = api.count(query[:-1], facets=facets)

            _merge_custom_facets(tmp_facets, results)
            count += results['total']
            query = 'net:'

    # Run any remaining search query
    if query[-1] != ':':
        results = api.count(query[:-1], facets=facets)

        _merge_custom_facets(tmp_facets, results)
        count += results['total']

    # Convert the internal facets structure back to the one that
    # the API returns.
    new_facets = {}
    for facet in tmp_facets:
        sorted_items = sorted(tmp_facets[facet].items(), key=itemgetter(1), reverse=True)
        new_facets[facet] = [{'value': key, 'count': value} for key, value in sorted_items]

    # Make sure the facet keys exist even if there weren't any results
    for facet, _ in facets:
        if facet not in new_facets:
            new_facets[facet] = []

    return {
        'matches': [],
        'facets': new_facets,
        'total': count,
    }


@click.group()
def alert():
    """Manage the network alerts for your account"""
    pass


@alert.command(name='clear')
def alert_clear():
    """Remove all alerts"""
    key = get_api_key()

    # Get the list
    api = shodan.Shodan(key)
    try:
        alerts = api.alerts()
        for alert in alerts:
            click.echo(u'Removing {} ({})'.format(alert['name'], alert['id']))
            api.delete_alert(alert['id'])
    except shodan.APIError as e:
        raise click.ClickException(e.value)
    click.echo("Alerts deleted")


@alert.command(name='create')
@click.argument('name', metavar='<name>')
@click.argument('netblocks', metavar='<netblocks>', nargs=-1)
def alert_create(name, netblocks):
    """Create a network alert to monitor an external network"""
    key = get_api_key()

    # Get the list
    api = shodan.Shodan(key)
    try:
        alert = api.create_alert(name, netblocks)
    except shodan.APIError as e:
        raise click.ClickException(e.value)

    click.secho('Successfully created network alert!', fg='green')
    click.secho('Alert ID: {}'.format(alert['id']), fg='cyan')


@alert.command(name='domain')
@click.argument('domain', metavar='<domain>', type=str)
@click.option('--triggers', help='List of triggers to enable', default='malware,industrial_control_system,internet_scanner,iot,open_database,new_service,ssl_expired,vulnerable')
def alert_domain(domain, triggers):
    """Create a network alert based on a domain name"""
    key = get_api_key()

    api = shodan.Shodan(key)
    try:
        # Grab a list of IPs for the domain
        domain = domain.lower()
        click.secho('Looking up domain information...', dim=True)
        info = api.dns.domain_info(domain, type='A')
        domain_ips = set([record['value'] for record in info['data']])

        # Create the actual alert
        click.secho('Creating alert...', dim=True)
        alert = api.create_alert('__domain: {}'.format(domain), list(domain_ips))

        # Enable the triggers so it starts getting managed by Shodan Monitor
        click.secho('Enabling triggers...', dim=True)
        api.enable_alert_trigger(alert['id'], triggers)
    except shodan.APIError as e:
        raise click.ClickException(e.value)

    click.secho('Successfully created domain alert!', fg='green')
    click.secho('Alert ID: {}'.format(alert['id']), fg='cyan')


@alert.command(name='download')
@click.argument('filename', metavar='<filename>', type=str)
@click.option('--alert-id', help='Specific alert ID to download the data of', default=None)
def alert_download(filename, alert_id):
    """Download all information for monitored networks/ IPs."""
    key = get_api_key()

    api = shodan.Shodan(key)
    ips = set()
    networks = set()

    # Helper method to process batches of IPs
    def batch(iterable, size=1):
        iter_length = len(iterable)
        for ndx in range(0, iter_length, size):
            yield iterable[ndx:min(ndx + size, iter_length)]

    try:
        # Get the list of alerts for the user
        click.echo('Looking up alert information...')
        if alert_id:
            alerts = [api.alerts(aid=alert_id.strip())]
        else:
            alerts = api.alerts()
        
        click.echo('Compiling list of networks/ IPs to download...')
        for alert in alerts:
            for net in alert['filters']['ip']:
                if '/' in net:
                    networks.add(net)
                else:
                    ips.add(net)
        
        click.echo('Downloading...')
        with open_file(filename) as fout:
            # Check if the user is able to use batch IP lookups
            batch_size = 1
            if len(ips) > 0:
                api_info = api.info()
                if api_info['plan'] in ['corp', 'stream-100']:
                    batch_size = 100
            
            # Convert it to a list so we can index into it
            ips = list(ips)

            # Grab all the IP information
            for ip in batch(ips, size=batch_size):
                try:
                    click.echo(ip)
                    results = api.host(ip)
                    if not isinstance(results, list):
                        results = [results]
                    
                    for host in results:
                        for banner in host['data']:
                            write_banner(fout, banner)
                except APIError:
                    pass
                sleep(1)  # Slow down a bit to make sure we don't hit the rate limit
            
            # Grab all the network ranges
            for net in networks:
                try:
                    counter = 0
                    click.echo(net)
                    for banner in api.search_cursor('net:{}'.format(net)):
                        write_banner(fout, banner)
                        
                        # Slow down a bit to make sure we don't hit the rate limit
                        if counter % 100 == 0:
                            sleep(1)
                        counter += 1
                except APIError:
                    pass
    except shodan.APIError as e:
        raise click.ClickException(e.value)
    
    click.secho('Successfully downloaded results into: {}'.format(filename), fg='green')


@alert.command(name='info')
@click.argument('alert', metavar='<alert id>')
def alert_info(alert):
    """Show information about a specific alert"""
    key = get_api_key()
    api = shodan.Shodan(key)

    try:
        info = api.alerts(aid=alert)
    except shodan.APIError as e:
        raise click.ClickException(e.value)

    click.secho(info['name'], fg='cyan')
    click.secho('Created: ', nl=False, dim=True)
    click.secho(info['created'], fg='magenta')

    click.secho('Notifications: ', nl=False, dim=True)
    if 'triggers' in info and info['triggers']:
        click.secho('enabled', fg='green')
    else:
        click.echo('disabled')

    click.echo('')
    click.secho('Network Range(s):', dim=True)

    for network in info['filters']['ip']:
        click.echo(u' > {}'.format(click.style(network, fg='yellow')))

    click.echo('')
    if 'triggers' in info and info['triggers']:
        click.secho('Triggers:', dim=True)
        for trigger in info['triggers']:
            click.echo(u' > {}'.format(click.style(trigger, fg='yellow')))
        click.echo('')


@alert.command(name='list')
@click.option('--expired', help='Whether or not to show expired alerts.', default=True, type=bool)
def alert_list(expired):
    """List all the active alerts"""
    key = get_api_key()

    # Get the list
    api = shodan.Shodan(key)
    try:
        results = api.alerts(include_expired=expired)
    except shodan.APIError as e:
        raise click.ClickException(e.value)

    if len(results) > 0:
        click.echo(u'# {:14} {:<21} {:<15s}'.format('Alert ID', 'Name', 'IP/ Network'))

        for alert in results:
            click.echo(
                u'{:16} {:<30} {:<35} '.format(
                    click.style(alert['id'], fg='yellow'),
                    click.style(alert['name'], fg='cyan'),
                    click.style(', '.join(alert['filters']['ip']), fg='white')
                ),
                nl=False
            )

            if 'triggers' in alert and alert['triggers']:
                click.secho('Triggers: ', fg='magenta', nl=False)
                click.echo(', '.join(alert['triggers'].keys()), nl=False)

            if 'expired' in alert and alert['expired']:
                click.secho('expired', fg='red')
            else:
                click.echo('')
    else:
        click.echo("You haven't created any alerts yet.")


@alert.command(name='stats')
@click.option('--limit', help='The number of results to return.', default=10, type=int)
@click.option('--filename', '-O', help='Save the results in a CSV file of the provided name.', default=None)
@click.argument('facets', metavar='<facets ...>', nargs=-1)
def alert_stats(limit, filename, facets):
    """Show summary information about your monitored networks"""
    # Setup Shodan
    key = get_api_key()
    api = shodan.Shodan(key)

    # Make sure the user didn't supply an empty string
    if not facets:
        raise click.ClickException('No facets provided')

    facets = [(facet, limit) for facet in facets]

    # Get the list of IPs/ networks that the user is monitoring
    networks = set()
    try:
        alerts = api.alerts()
        for alert in alerts:
            for tmp in alert['filters']['ip']:
                networks.add(tmp)
    except shodan.APIError as e:
        raise click.ClickException(e.value)

    # Grab the facets the user requested
    try:
        results = aggregate_facet(api, networks, facets)
    except shodan.APIError as e:
        raise click.ClickException(e.value)

    # TODO: The below code was taken from __main__.py:stats() - we should refactor it so the code can be shared
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


@alert.command(name='remove')
@click.argument('alert_id', metavar='<alert ID>')
def alert_remove(alert_id):
    """Remove the specified alert"""
    key = get_api_key()

    # Get the list
    api = shodan.Shodan(key)
    try:
        api.delete_alert(alert_id)
    except shodan.APIError as e:
        raise click.ClickException(e.value)
    click.echo("Alert deleted")


@alert.command(name='triggers')
def alert_list_triggers():
    """List the available notification triggers"""
    key = get_api_key()

    # Get the list
    api = shodan.Shodan(key)
    try:
        results = api.alert_triggers()
    except shodan.APIError as e:
        raise click.ClickException(e.value)

    if len(results) > 0:
        click.secho('The following triggers can be enabled on alerts:', dim=True)
        click.echo('')

        for trigger in sorted(results, key=itemgetter('name')):
            click.secho('{:<12} '.format('Name'), dim=True, nl=False)
            click.secho(trigger['name'], fg='yellow')

            click.secho('{:<12} '.format('Description'), dim=True, nl=False)
            click.secho(trigger['description'], fg='cyan')

            click.secho('{:<12} '.format('Rule'), dim=True, nl=False)
            click.echo(trigger['rule'])

            click.echo('')
    else:
        click.echo("No triggers currently available.")


@alert.command(name='enable')
@click.argument('alert_id', metavar='<alert ID>')
@click.argument('trigger', metavar='<trigger name>')
def alert_enable_trigger(alert_id, trigger):
    """Enable a trigger for the alert"""
    key = get_api_key()

    # Get the list
    api = shodan.Shodan(key)
    try:
        api.enable_alert_trigger(alert_id, trigger)
    except shodan.APIError as e:
        raise click.ClickException(e.value)

    click.secho('Successfully enabled the trigger: {}'.format(trigger), fg='green')


@alert.command(name='disable')
@click.argument('alert_id', metavar='<alert ID>')
@click.argument('trigger', metavar='<trigger name>')
def alert_disable_trigger(alert_id, trigger):
    """Disable a trigger for the alert"""
    key = get_api_key()

    # Get the list
    api = shodan.Shodan(key)
    try:
        api.disable_alert_trigger(alert_id, trigger)
    except shodan.APIError as e:
        raise click.ClickException(e.value)

    click.secho('Successfully disabled the trigger: {}'.format(trigger), fg='green')
