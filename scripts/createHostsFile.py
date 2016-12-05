import getopt
import json
import sys


def main(argv):
    domainsFile = ''

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
            domainsFile = arg

    if not domainsFile:
        print('createHostsFile.py: ERROR: Missing parameter --domainsfile')
        sys.exit(2)

    with open(domainsFile, 'r') as myfile:
        domains = myfile.read()

    domainsJSON = json.loads(domains)

    hosts = []

    for orgRecord in domainsJSON['organizations']:
        for hostRecord in orgRecord['hosts']:
            host = hostRecord.get('host', '')

            if host != '' and ':' not in host:
                hosts.append(host)

    print('\n'.join(sorted(set(hosts))))

if __name__ == '__main__':
    main(sys.argv[1:])
