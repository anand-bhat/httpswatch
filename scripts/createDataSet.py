import datetime
import getopt
import json
import sys
import requests

requests.packages.urllib3.disable_warnings()


def valueIfGraded(grade, value):
    return (value if grade != '' else '-')


def booleanToYesNo(value):
    return ('Yes' if value else 'No')


def getExtraHostData(jsonData, host, key):
    for orgRecord in jsonData['organizations']:
        for hostRecord in orgRecord['hosts']:
            if hostRecord.get('host', '?') in [host, '*']:
                if key == 'organization':
                    return orgRecord.get('organization', '?')
                return hostRecord.get(key, '?')

    return '?'


def openSslCcsValue(value):
    switcher = {
        -1: 'Test failure',
        0: 'Unknown',
        1: 'No',
        2: 'Possibly',
        3: 'Yes'
    }
    return switcher.get(value, '-')


def openSSLLuckyMinus20Value(value):
    switcher = {
        -1: 'Test failure',
        0: 'Unknown',
        1: 'No',
        2: 'Yes'
    }
    return switcher.get(value, '-')


def ticketbleedValue(value):
    switcher = {
        -1: 'Test failure',
        0: 'Unknown',
        1: 'No',
        2: 'Yes'
    }
    return switcher.get(value, '-')


def lacksFSValue(value):
    return ('Yes' if value in [0, 1]
            else 'No' if value in [2, 4]
            else '')


def poodleTlsValue(value):
    switcher = {
        -3: 'Test timeout',
        -2: 'No',
        -1: 'Test failure',
        0: 'Unknown',
        1: 'No',
        2: 'Yes'
    }
    return switcher.get(value, '-')


def isBitSet(x, n):
    return (x & 2**n != 0)


def hasSecureEndpoint(ssllabsJSON, hostToBeChecked):
    for labsReport in ssllabsJSON:
        if labsReport['host'] != hostToBeChecked:
            continue

        if labsReport['status'] != 'READY':
            continue

        return(hasSecureIPEndpoint(labsReport['endpoints']))
    return False


def hasSecureIPEndpoint(endpoints):
    failures = ['No secure protocols supported',
                'Unable to connect to the server']
    for endpoint in endpoints:
        if endpoint.get('statusMessage', '') not in failures:
            return True
    return False


def updateCounts(table, key):
    if key in table:
        table[key] = table[key] + 1
    else:
        table[key] = 1
    return table


def updateCountsByOrg(table, org, key):
    if key.startswith('T/'):
        key = 'T'

    if org in table:
        counts = table[org]
        return updateCounts(counts, key)

    counts = {}
    counts[key] = 1
    table[org] = counts
    return table


def printChartDataCountsByOrg(table):
    print('var chartDataCountsByOrg = [')
    print('[\'Organization\', ' +
          '{label: \'A+\', type: \'number\'}, ' +
          '{label: \'A\', type: \'number\'}, ' +
          '{label: \'A-\', type: \'number\'}, ' +
          '{label: \'B\', type: \'number\'}, ' +
          '{label: \'C\', type: \'number\'}, ' +
          '{label: \'D\', type: \'number\'}, ' +
          '{label: \'E\', type: \'number\'}, ' +
          '{label: \'T\', type: \'number\'}, ' +
          '{label: \'F\', type: \'number\'}, ' +
          '{label: \'No HTTPS\', type: \'number\'}, ' +
          '{label: \'Scan error\', type: \'number\'}, ' +
          '{label: \'Not scanned\', type: \'number\'}],')
    for org in sorted(table.keys()):
        counts = table[org]
        print('[\'' + org + '\', ' + getVal(counts, 'A+') + ', ' +
              getVal(counts, 'A') + ', ' + getVal(counts, 'A-') + ', ' +
              getVal(counts, 'B') + ', ' + getVal(counts, 'C') + ', ' +
              getVal(counts, 'D') + ', ' + getVal(counts, 'E') + ', ' +
              getVal(counts, 'T') + ', ' + getVal(counts, 'F') + ', ' +
              getVal(counts, 'No HTTPS') + ', ' +
              getVal(counts, 'Scan error') + ', ' +
              getVal(counts, 'Not scanned') + '],')
    print('];')


def getVal(table, key):
    if key in table:
        return str(table[key])
    return 'null'


def printChartDataSummary(table):
    print('var chartDataSummary = [')
    print('[\'Grade\', \'Number of sites\', {role: \'style\'}],')

    printCount(table, 'A+', 'A+', ', \'color: Green\'],')
    printCount(table, 'A', 'A', ', \'color: YellowGreen\'],')
    printCount(table, 'A-', 'A-', ', \'color: LightGreen\'],')
    printCount(table, 'B', 'B', ', \'color: Orange\'],')
    printCount(table, 'C', 'C', ', \'color: Orange\'],')
    printCount(table, 'D', 'D', ', \'color: Red\'],')
    printCount(table, 'E', 'E', ', \'color: Red\'],')
    printCount(table, 'T', 'T', ', \'color: Red\'],')
    printCount(table, 'T/ A+', 'T/ A+', ', \'color: Red\'],')
    printCount(table, 'T/ A', 'T/ A', ', \'color: Red\'],')
    printCount(table, 'T/ A-', 'T/ A-', ', \'color: Red\'],')
    printCount(table, 'T/ B', 'T/ B', ', \'color: Red\'],')
    printCount(table, 'T/ C', 'T/ C', ', \'color: Red\'],')
    printCount(table, 'T/ D', 'T/ D', ', \'color: Red\'],')
    printCount(table, 'T/ E', 'T/ E', ', \'color: Red\'],')
    printCount(table, 'T/ F', 'T/ F', ', \'color: Red\'],')
    printCount(table, 'F', 'F', ', \'color: Red\'],')
    printCount(table, 'No HTTPS', 'No HTTPS', ', \'color: Red\'],')
    printCount(table, 'Scan error', 'Scan error', ', \'color: Gray\'],')
    printCount(table, 'Not scanned', 'Not scanned', ', \'color: Gray\'],')
    printCount(table, 'Unknown domain', 'Unknown domain',
               ', \'color: Gray\'],')
    printCount(table, 'Could not connect', 'Could not connect',
               ', \'color: Gray\'],')

    print('];')


def printCount(table, key, printVal, extra):
    if key in table:
        print('[\'' + printVal + '\', ' + str(table[key]) + extra)


def canConnect(url):
    try:
        req = requests.get(url, allow_redirects=False, verify=False, timeout=5)
        return 1
    except:
        return 0


def main(argv):
    domainsFile = ''
    ssllabsReportsFile = ''

    # Commmand line requirements
    try:
        opts, args = getopt.getopt(
            argv, 'h:d:s', ['domainsfile=', 'ssllabsreportsfile='])
    except getopt.GetoptError:
        print('createDataSet.py -d <domainsJSON> -s <SSLLabsReportsJSON>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('createDataSet.py -d <domainsJSON> -s <SSLLabsReportsJSON>')
            sys.exit()
        elif opt in ('-d', '--domainsfile'):
            domainsFile = arg
        elif opt in ('-s', '--ssllabsreportsfile'):
            ssllabsReportsFile = arg

    if not domainsFile or not ssllabsReportsFile:
        print('createDataSet.py -d <domainsJSON> -s <SSLLabsReportsJSON>')
        sys.exit(2)

    # Read domains JSON
    with open(domainsFile, 'r') as myfile:
        domains = myfile.read()

    domainsJSON = json.loads(domains)

    # Read SSL Labs report
    with open(ssllabsReportsFile, 'r') as myfile:
        ssllabsReports = myfile.read()

    ssllabsJSON = json.loads(ssllabsReports)

    countsSummary = {}
    countsByOrg = {}
    hostsFromSSLLabsReport = []

    # Start creating dataSet
    print('var dataSet = [')

    for labsReport in ssllabsJSON:
        host = labsReport['host']
        status = labsReport['status']
        statusMessage = labsReport.get('statusMessage', '')

        # Keep track of host scanned by SSL Labs
        hostsFromSSLLabsReport.append(host)

        # Fetch additional data from domains JSON
        industry = domainsJSON.get('industry', '')
        org = getExtraHostData(domainsJSON, host, 'organization')
        hostPurpose = getExtraHostData(domainsJSON, host, 'hostPurpose')
        httpsBehavior = getExtraHostData(domainsJSON, host, 'httpsBehavior')
        issueReport = getExtraHostData(domainsJSON, host, 'issueReport')
        if issueReport == '?':
            issueReport = '-'

        # Handle cases where SSL Labs scan failed to run. Cases:
        # 1. SSL Labs was unable to resolve the domain name (flaky DNS)
        # 2. Other unknown situations where status is 'ERROR'
        if status != 'READY':
            if (statusMessage == 'Unable to resolve domain name'):
                grade = 'Unknown domain'
            elif (status == 'ERROR'):
                grade = 'Scan error'

            # Print record
            dataSetValues = ['', org, host, '-', grade, '-',
                             statusMessage, industry, hostPurpose,
                             httpsBehavior, issueReport, '-', '-', '-', '-',
                             '-', '-', '-', '-', '-', '-', '-', '-', '-', '-',
                             '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-']
            print(dataSetValues, ',')

            # Update chart data
            updateCounts(countsSummary, grade)
            updateCountsByOrg(countsByOrg, org, grade)

            # Proceed to next record in SSL Labs scan data
            continue

        # Obtain certificate details
        certKeyStrength = -1
        certIssues = 0
        for cert in labsReport['certs']:
            certKeyStrength = cert.get('keyStrength', -1)
            certIssues = cert.get('issues', 0)
            break

        numberOfEndpoints = len(labsReport['endpoints'])

        # Repeat for each endpoint for a given host
        for endpoint in labsReport['endpoints']:
            ipAddress = endpoint['ipAddress']
            grade = endpoint.get('grade', '')
            statusMessage = endpoint.get('statusMessage', '')

            if 'details' not in endpoint:
                continue

            # Test time in user-friendly format
            testTime = datetime.datetime.fromtimestamp(
                endpoint['details'].get(
                    'hostStartTime', 0)/1000.0).strftime('%Y-%m-%d')

            # Determine if site supports RC4
            supportsRc4 = valueIfGraded(
                grade, booleanToYesNo(
                    endpoint['details'].get('supportsRc4', False)))

            # Determine if site lacks Forward Secrecy with reference browsers
            lacksFS = valueIfGraded(
                grade, lacksFSValue(
                    endpoint['details'].get('forwardSecrecy', '-')))

            # Determine if site uses RC4 suites with modern protocols
            rc4WithModern = valueIfGraded(
                grade, booleanToYesNo(
                    endpoint['details'].get('rc4WithModern', False)))

            # Determine if site is vulnerable to Heartbleed
            heartbleed = valueIfGraded(
                grade, booleanToYesNo(
                    endpoint['details'].get('heartbleed', False)))

            # Determine if site is vulnerable to POODLE (SSL)
            poodle = valueIfGraded(
                grade, booleanToYesNo(
                    endpoint['details'].get('poodle', False)))

            # Determine if site is vulnerable to POODLE (TLS)
            poodleTls = valueIfGraded(
                grade, poodleTlsValue(
                    endpoint['details'].get('poodleTls', '-')))

            # Determine if site is vulnerable to FREAK
            freak = valueIfGraded(
                grade, booleanToYesNo(endpoint['details'].get('freak', False)))

            # Determine if site is vulnerable to Logjam
            logjam = valueIfGraded(
                grade, booleanToYesNo(
                    endpoint['details'].get('logjam', False)))

            # Determine if site is vulnerable to CVE-2014-0224
            openSslCcs = valueIfGraded(
                grade, openSslCcsValue(
                    endpoint['details'].get('openSslCcs', '-')))

            # Determine if site is vulnerable to CVE-2016-2107
            openSSLLuckyMinus20 = valueIfGraded(
                grade, openSSLLuckyMinus20Value(
                    endpoint['details'].get('openSSLLuckyMinus20', '-')))

            # Determine if site is vulnerable to Ticketbleed (CVE-2016-9244)
            ticketbleed = valueIfGraded(
                grade, ticketbleedValue(
                    endpoint['details'].get('ticketbleed', '-')))

            # Determine if site supports insecure renegotiation
            insecureRenegotiation = valueIfGraded(
                grade, booleanToYesNo(
                    isBitSet(endpoint['details'].get('renegSupport', 0), 0)))

            # Determine if site lacks support for secure renegotiation
            lacksSecureRenegotiation = valueIfGraded(
                grade, booleanToYesNo(
                    not isBitSet(
                        endpoint['details'].get('renegSupport', 0), 1)))

            # Determine if site has weak private key
            weakPrivateKey = valueIfGraded(
                grade, booleanToYesNo(certKeyStrength <= 1024))

            # Protocol analysis - Check for SSL2.0, SSL3.0, lack of TLS, TLS1.2
            sslv2 = False
            sslv3 = False
            notls = True
            notlsv12 = True

            for protocol in endpoint['details']['protocols']:
                protocolName = protocol['name']
                protocolVersion = protocol['version']

                if (protocolName == 'SSL'):
                    if (protocolVersion == '2.0'):
                        sslv2 = True
                        continue
                    elif (protocolVersion == '3.0'):
                        sslv3 = True
                        continue
                elif (protocolName == 'TLS'):
                    notls = False
                    if (protocolVersion == '1.2'):
                        notlsv12 = False

            # Determine if site is vulnerable to DROWN
            drownVulnerable = valueIfGraded(
                grade, booleanToYesNo(
                    sslv2 or
                    endpoint['details'].get('drownVulnerable', False)))

            sslv2 = valueIfGraded(grade, booleanToYesNo(sslv2))
            sslv3 = valueIfGraded(grade, booleanToYesNo(sslv3))
            notls = valueIfGraded(grade, booleanToYesNo(notls))
            notlsv12 = valueIfGraded(grade, booleanToYesNo(notlsv12))

            # Determine if site supports anonymous suites and uses weak DH
            supportsAnonSuites = False
            weakDH = False
            weakCiphers = False
            if 'suites' in endpoint['details']:
                for suiteSet in endpoint['details']['suites']:
                    for suite in suiteSet['list']:
                        if not supportsAnonSuites and 'anon' in suite['name']:
                            supportsAnonSuites = True
                        if not weakDH and suite.get('kxType', '') == 'DH' and suite.get('kxStrength', 99999) <= 1024:
                            weakDH = True
                        if not weakCiphers and suite.get('cipherStrength', 99999) < 112:
                            weakCiphers = True

            supportsAnonSuites = valueIfGraded(
                grade, booleanToYesNo(supportsAnonSuites))
            weakDH = valueIfGraded(grade, booleanToYesNo(weakDH))
            weakCiphers = valueIfGraded(grade, booleanToYesNo(weakCiphers))

            sweet32 = False
            if 'sims' in endpoint['details']:
                for sim in endpoint['details']['sims']['results']:
                    if not sweet32 and sim.get('protocolId', 0) in ['770', '771'] and ('IDEA' in sim.get('suiteName', '') or '3DES' in sim.get('suiteName', '')):
                        sweet32 = True

            sweet32 = valueIfGraded(grade, booleanToYesNo(sweet32))

            # Determine if site only supports RC4
            rc4Only = valueIfGraded(
                grade, booleanToYesNo(
                    endpoint['details'].get('rc4Only', False)))

            # Determine if certificate chain is incomplete
            hasIncompleteChain = False
            for certChain in endpoint['details']['certChains']:
                if (isBitSet(certChain.get('issues', 0), 1)):
                    hasIncompleteChain = True
                    break

            hasIncompleteChain = valueIfGraded(
                grade, booleanToYesNo(hasIncompleteChain))

            # Determine trust issues
            trustIssues = False
            if (grade == 'T'):
                trustIssues = True
                grade = grade + '/ ' + endpoint.get('gradeTrustIgnored', '')
            elif (grade == 'F' and certIssues != 0):
                trustIssues = True

            trustIssues = valueIfGraded(
                    grade, booleanToYesNo(trustIssues))

            # Determine user defined grade when SSL Labs fails to scan
            if (grade == ''):
                if (statusMessage == 'No secure protocols supported'):
                    grade = 'No HTTPS'
                elif (statusMessage == 'Unable to connect to the server'):
                    # Check if at least one endpoint is secure
                    if (numberOfEndpoints > 1 and
                            hasSecureEndpoint(ssllabsJSON, host)):
                        # Endpoint is probably not accepting traffic
                        grade = 'Could not connect'
                    else:
                        # Check if host can be reached via HTTP
                        if (canConnect('http://' + host)):
                            grade = 'No HTTPS'
                        else:
                            grade = 'Could not connect'
                else:
                    grade = 'Scan error'

            # Print record
            dataSetValues = ['', org, host, ipAddress, grade, testTime,
                             statusMessage, industry, hostPurpose,
                             httpsBehavior, issueReport, heartbleed,
                             openSslCcs, openSSLLuckyMinus20, freak, logjam,
                             poodleTls, drownVulnerable, ticketbleed, sslv2,
                             supportsAnonSuites, rc4Only,
                             insecureRenegotiation, notls, weakCiphers, trustIssues, poodle,
                             notlsv12, rc4WithModern, sweet32, supportsRc4, sslv3,
                             weakDH, hasIncompleteChain, weakPrivateKey,
                             lacksFS, lacksSecureRenegotiation]
            print(dataSetValues, ',')

            # Update chart data
            updateCounts(countsSummary, grade)
            updateCountsByOrg(countsByOrg, org, grade)

    # Handle hosts from domains list that were not scanned. Cases:
    # 1. Hosts on ports other than 443 cannot be scanned using SSL Labs
    # 2. SSL Labs sometimes appears to skip records from the input file)
    industry = domainsJSON.get('industry', '')
    for orgRecord in domainsJSON['organizations']:
        org = orgRecord.get('organization', '')
        for hostRecord in orgRecord['hosts']:
            host = hostRecord.get('host', '')

            httpsBehavior = hostRecord.get('httpsBehavior', '')
            if (host == '' or host == '*' or
                    host in hostsFromSSLLabsReport):
                continue

            hostPurpose = hostRecord.get('hostPurpose', '')
            issueReport = hostRecord.get('issueReport', '')

            # Print record
            dataSetValues = ['', org, host, '-', 'Not scanned', '-',
                             'Not scanned', industry, hostPurpose,
                             httpsBehavior, issueReport, '-', '-', '-', '-',
                             '-', '-', '-', '-', '-', '-', '-', '-', '-', '-',
                             '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-']
            print(dataSetValues, ',')

            # Update chart data
            updateCounts(countsSummary, 'Not scanned')
            updateCountsByOrg(countsByOrg, org, 'Not scanned')

    # Terminate dataSet
    print('];')

    # Print chart data
    printChartDataSummary(countsSummary)
    printChartDataCountsByOrg(countsByOrg)


if __name__ == '__main__':
    main(sys.argv[1:])
