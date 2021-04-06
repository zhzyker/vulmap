import click
from thirdparty import requests
from thirdparty import shodan
import thirdparty.shodan.helpers as helpers

from thirdparty.shodan.cli.helpers import get_api_key


@click.group()
def data():
    """Bulk data access to Shodan"""
    pass


@data.command(name='list')
@click.option('--dataset', help='See the available files in the given dataset', default=None, type=str)
def data_list(dataset):
    """List available datasets or the files within those datasets."""
    # Setup the API connection
    key = get_api_key()
    api = shodan.Shodan(key)

    if dataset:
        # Show the files within this dataset
        files = api.data.list_files(dataset)

        for file in files:
            click.echo(click.style(u'{:20s}'.format(file['name']), fg='cyan'), nl=False)
            click.echo(click.style('{:10s}'.format(helpers.humanize_bytes(file['size'])), fg='yellow'), nl=False)

            # Show the SHA1 checksum if available
            if file.get('sha1'):
                click.echo(click.style('{:42s}'.format(file['sha1']), fg='green'), nl=False)
            
            click.echo('{}'.format(file['url']))
    else:
        # If no dataset was provided then show a list of all datasets
        datasets = api.data.list_datasets()

        for ds in datasets:
            click.echo(click.style('{:15s}'.format(ds['name']), fg='cyan'), nl=False)
            click.echo('{}'.format(ds['description']))


@data.command(name='download')
@click.option('--chunksize', help='The size of the chunks that are downloaded into memory before writing them to disk.', default=1024, type=int)
@click.option('--filename', '-O', help='Save the file as the provided filename instead of the default.')
@click.argument('dataset', metavar='<dataset>')
@click.argument('name', metavar='<file>')
def data_download(chunksize, filename, dataset, name):
    # Setup the API connection
    key = get_api_key()
    api = shodan.Shodan(key)

    # Get the file object that the user requested which will contain the URL and total file size
    file = None
    try:
        files = api.data.list_files(dataset)
        for tmp in files:
            if tmp['name'] == name:
                file = tmp
                break
    except shodan.APIError as e:
        raise click.ClickException(e.value)

    # The file isn't available
    if not file:
        raise click.ClickException('File not found')

    # Start downloading the file
    response = requests.get(file['url'], stream=True)

    # Figure out the size of the file based on the headers
    filesize = response.headers.get('content-length', None)
    if not filesize:
        # Fall back to using the filesize provided by the API
        filesize = file['size']
    else:
        filesize = int(filesize)

    chunk_size = 1024
    limit = filesize / chunk_size

    # Create a default filename based on the dataset and the filename within that dataset
    if not filename:
        filename = '{}-{}'.format(dataset, name)

    # Open the output file and start writing to it in chunks
    with open(filename, 'wb') as fout:
        with click.progressbar(response.iter_content(chunk_size=chunk_size), length=limit) as bar:
            for chunk in bar:
                if chunk:
                    fout.write(chunk)

    click.echo(click.style('Download completed: {}'.format(filename), 'green'))
