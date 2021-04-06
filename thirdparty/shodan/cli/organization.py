import click
from thirdparty import shodan

from thirdparty.shodan.cli.helpers import get_api_key, humanize_api_plan


@click.group()
def org():
    """Manage your organization's access to Shodan"""
    pass


@org.command()
@click.option('--silent', help="Don't send a notification to the user", default=False, is_flag=True)
@click.argument('user', metavar='<username or email>')
def add(silent, user):
    """Add a new member"""
    key = get_api_key()
    api = shodan.Shodan(key)

    try:
        api.org.add_member(user, notify=not silent)
    except shodan.APIError as e:
        raise click.ClickException(e.value)

    click.secho('Successfully added the new member', fg='green')


@org.command()
def info():
    """Show an overview of the organization"""
    key = get_api_key()
    api = shodan.Shodan(key)
    try:
        organization = api.org.info()
    except shodan.APIError as e:
        raise click.ClickException(e.value)

    click.secho(organization['name'], fg='cyan')
    click.secho('Access Level: ', nl=False, dim=True)
    click.secho(humanize_api_plan(organization['upgrade_type']), fg='magenta')

    if organization['domains']:
        click.secho('Authorized Domains: ', nl=False, dim=True)
        click.echo(', '.join(organization['domains']))

    click.echo('')
    click.secho('Administrators:', dim=True)

    for admin in organization['admins']:
        click.echo(u' > {:30}\t{:30}'.format(
            click.style(admin['username'], fg='yellow'),
            admin['email'])
        )

    click.echo('')
    if organization['members']:
        click.secho('Members:', dim=True)
        for member in organization['members']:
            click.echo(u' > {:30}\t{:30}'.format(
                click.style(member['username'], fg='yellow'),
                member['email'])
            )
    else:
        click.secho('No members yet', dim=True)


@org.command()
@click.argument('user', metavar='<username or email>')
def remove(user):
    """Remove and downgrade a member"""
    key = get_api_key()
    api = shodan.Shodan(key)

    try:
        api.org.remove_member(user)
    except shodan.APIError as e:
        raise click.ClickException(e.value)

    click.secho('Successfully removed the member', fg='green')
