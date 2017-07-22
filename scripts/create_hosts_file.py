"""Creates a hosts file from the domains JSON file."""

import getopt
import json
import sys


def main(argv):
    """Main function."""
    domains_file = ''

    try:
        opts, args = getopt.getopt(
            argv, 'h:d', ['domainsfile='])
    except getopt.GetoptError:
        print('createHostsFile.py -d <domainsJSON>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('createHostsFile.py -d <domainsJSON>')
            sys.exit()
        elif opt in ('-d', '--domainsfile'):
            domains_file = arg

    if not domains_file:
        print('createHostsFile.py: ERROR: Missing parameter --domainsfile')
        sys.exit(2)

    with open(domains_file, 'r') as myfile:
        domains = myfile.read()

    domains_json = json.loads(domains)

    hosts = []

    for org_record in domains_json['organizations']:
        for host_record in org_record['hosts']:
            host = host_record.get('host', '')

            if host != '' and ':' not in host:
                hosts.append(host)

    print('\n'.join(sorted(set(hosts))))


if __name__ == '__main__':
    main(sys.argv[1:])
