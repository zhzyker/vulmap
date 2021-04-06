from json import dumps
from .base import Converter
from ...helpers import get_ip, iterate_files


class GeoJsonConverter(Converter):

    def header(self):
        self.fout.write("""{
            "type": "FeatureCollection",
            "features": [
        """)

    def footer(self):
        self.fout.write("""{ }]}""")

    def process(self, files):
        # Write the header
        self.header()

        # We only want to generate 1 datapoint for each IP - not per service
        unique_hosts = set()
        for banner in iterate_files(files):
            ip = get_ip(banner)
            if not ip:
                continue

            if ip not in unique_hosts:
                self.write(ip, banner)
                unique_hosts.add(ip)

        self.footer()

    def write(self, ip, host):
        try:
            lat, lon = host['location']['latitude'], host['location']['longitude']
            feature = {
                'type': 'Feature',
                'id': ip,
                'properties': {
                    'name': ip,
                    'lat': lat,
                    'lon': lon,
                },
                'geometry': {
                    'type': 'Point',
                    'coordinates': [lon, lat],
                },
            }
            self.fout.write(dumps(feature) + ',')
        except Exception:
            pass
