from urllib.parse import urlparse
import gzip
import urllib.request
import json
from collections import Counter


feed_urls = []
for year in range(2002, 2019):
    feed_urls.append('https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-%s.json.gz' % year)


references = []

for url in feed_urls:
    print('Getting %s' % url)
    response = urllib.request.urlopen(url)
    data = json.loads(gzip.decompress(response.read()))
    for item in data['CVE_Items']:
        for url in item['cve']['references']['reference_data']:
            references.append(url['url'])

domains = []

for line in references:
    parsed_uri = urlparse(line)
    domain = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)
    domains.append(domain)

print('Top references:')
for i in list(Counter(domains).most_common(50)):
    print(i)
print('Total references found: %s' % len(domains))
