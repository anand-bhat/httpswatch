"""Creates data set for datatables using SSLLabs report."""

import datetime
import getopt
import json
import sys
import requests

requests.packages.urllib3.disable_warnings()


def main(argv):
    """Main function."""
    domains_file = ''
    ssllabs_reports_file = ''

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
            domains_file = arg
        elif opt in ('-s', '--ssllabsreportsfile'):
            ssllabs_reports_file = arg

    if not domains_file or not ssllabs_reports_file:
        print('createDataSet.py -d <domainsJSON> -s <SSLLabsReportsJSON>')
        sys.exit(2)

    # Read domains JSON
    with open(domains_file, 'r') as myfile:
        domains = myfile.read()

    domains_json = json.loads(domains)

    # Read SSL Labs report
    with open(ssllabs_reports_file, 'r') as myfile:
        ssllabs_reports = myfile.read()

    ssllabs_json = json.loads(ssllabs_reports)

    counts_summary = {}
    counts_by_org = {}
    hosts_from_ssllabs_report = []

    # Start creating dataSet
    print('var dataSet = [')

    for labs_report in ssllabs_json:
        host = labs_report['host']
        status = labs_report['status']
        status_message = labs_report.get('statusMessage', '')

        # Keep track of host scanned by SSL Labs
        hosts_from_ssllabs_report.append(host)

        # Fetch additional data from domains JSON
        industry = domains_json.get('industry', '')
        org = get_extra_host_data(domains_json, host, 'organization')
        host_purpose = get_extra_host_data(domains_json, host, 'hostPurpose')
        https_behavior = get_extra_host_data(
            domains_json, host, 'httpsBehavior')
        issue_report = get_extra_host_data(domains_json, host, 'issueReport')
        if issue_report == '?':
            issue_report = '-'

        # Handle cases where SSL Labs scan failed to run. Cases:
        # 1. SSL Labs was unable to resolve the domain name (flaky DNS)
        # 2. Other unknown situations where status is 'ERROR'
        if status != 'READY':
            if status_message == 'Unable to resolve domain name':
                grade = 'Unknown domain'
            elif status == 'ERROR':
                grade = 'Scan error'

            # Print record
            data_set_values = ['', org, host, '-', grade, '-', status_message,
                               industry, host_purpose, https_behavior,
                               issue_report, '-', '-', '-', '-', '-', '-', '-',
                               '-', '-', '-', '-', '-', '-', '-', '-', '-',
                               '-', '-', '-', '-', '-', '-', '-', '-', '-',
                               '-', '-', '-']
            print(data_set_values, ',')

            # Update chart data
            update_counts(counts_summary, grade)
            update_counts_by_org(counts_by_org, org, grade)

            # Proceed to next record in SSL Labs scan data
            continue

        # Obtain certificate details
        cert_key_strength = -1
        cert_issues = 0
        for cert in labs_report['certs']:
            cert_key_strength = cert.get('keyStrength', -1)
            cert_issues = cert.get('issues', 0)
            break

        number_of_endpoints = len(labs_report['endpoints'])

        # Repeat for each endpoint for a given host
        for endpoint in labs_report['endpoints']:
            ip_address = endpoint['ipAddress']
            grade = endpoint.get('grade', '')
            status_message = endpoint.get('statusMessage', '')

            if 'details' not in endpoint:
                continue

            # Test time in user-friendly format
            test_time = datetime.datetime.fromtimestamp(
                endpoint['details'].get(
                    'hostStartTime', 0)/1000.0).strftime('%Y-%m-%d')

            # Determine if site supports RC4
            supports_rc4 = value_if_graded(
                grade, boolean_to_yes_no(
                    endpoint['details'].get('supportsRc4', False)))

            # Determine if site lacks Forward Secrecy with reference browsers
            lacks_fs = value_if_graded(
                grade, lacks_fs_value(
                    endpoint['details'].get('forwardSecrecy', '-')))

            # Determine if site uses RC4 suites with modern protocols
            rc4_with_modern = value_if_graded(
                grade, boolean_to_yes_no(
                    endpoint['details'].get('rc4WithModern', False)))

            # Determine if site is vulnerable to Heartbleed
            heartbleed = value_if_graded(
                grade, boolean_to_yes_no(
                    endpoint['details'].get('heartbleed', False)))

            # Determine if site is vulnerable to POODLE (SSL)
            poodle = value_if_graded(
                grade, boolean_to_yes_no(
                    endpoint['details'].get('poodle', False)))

            # Determine if site is vulnerable to POODLE (TLS)
            poodle_tls = value_if_graded(
                grade, poodle_tls_value(
                    endpoint['details'].get('poodleTls', '-')))

            # Determine if site is vulnerable to FREAK
            freak = value_if_graded(
                grade, boolean_to_yes_no(
                    endpoint['details'].get('freak', False)))

            # Determine if site is vulnerable to Logjam
            logjam = value_if_graded(
                grade, boolean_to_yes_no(
                    endpoint['details'].get('logjam', False)))

            # Determine if site is vulnerable to CVE-2014-0224
            openssl_ccs = value_if_graded(
                grade, opensl_ccs_value(
                    endpoint['details'].get('openSslCcs', '-')))

            # Determine if site is vulnerable to CVE-2016-2107
            openssl_lucky_minus20 = value_if_graded(
                grade, openssl_lucky_minus20_value(
                    endpoint['details'].get('openSSLLuckyMinus20', '-')))

            # Determine if site is vulnerable to Ticketbleed (CVE-2016-9244)
            ticketbleed = value_if_graded(
                grade, ticketbleed_value(
                    endpoint['details'].get('ticketbleed', '-')))

            # Determine if site is vulnerable to ROBOT
            robot = value_if_graded(
                grade, robot_value(
                    endpoint['details'].get('bleichenbacher', '-')))

            # Determine if site supports insecure renegotiation
            insecure_renegotiation = value_if_graded(
                grade, boolean_to_yes_no(
                    is_bit_set(endpoint['details'].get('renegSupport', 0), 0)))

            # Determine if site lacks support for secure renegotiation
            lacks_secure_renegotiation = value_if_graded(
                grade, boolean_to_yes_no(
                    not is_bit_set(
                        endpoint['details'].get('renegSupport', 0), 1)))

            # Determine if site has weak private key
            weak_private_key = value_if_graded(
                grade, boolean_to_yes_no(cert_key_strength <= 1024))

            # Determine if site does not support AEAD cipher suites
            lacks_aead = value_if_graded(
                grade, boolean_to_yes_no(
                    not endpoint['details'].get('supportsAead', True)))

            # Protocol analysis - Check for SSL2.0, SSL3.0, lack of TLS, TLS1.2
            sslv2 = False
            sslv3 = False
            notls = True
            notlsv12 = True

            for protocol in endpoint['details']['protocols']:
                protocol_name = protocol['name']
                protocol_version = protocol['version']

                if protocol_name == 'SSL':
                    if protocol_version == '2.0':
                        sslv2 = True
                        continue
                    elif protocol_version == '3.0':
                        sslv3 = True
                        continue
                elif protocol_name == 'TLS':
                    notls = False
                    if protocol_version == '1.2':
                        notlsv12 = False

            # Determine if site is vulnerable to DROWN
            drown_vulnerable = value_if_graded(
                grade, boolean_to_yes_no(
                    sslv2 or
                    endpoint['details'].get('drownVulnerable', False)))

            sslv2 = value_if_graded(grade, boolean_to_yes_no(sslv2))
            sslv3 = value_if_graded(grade, boolean_to_yes_no(sslv3))
            notls = value_if_graded(grade, boolean_to_yes_no(notls))
            notlsv12 = value_if_graded(grade, boolean_to_yes_no(notlsv12))

            # Determine if site supports anonymous suites and uses weak DH
            supports_anon_suites = False
            weak_dh = False
            weak_ciphers = False
            if 'suites' in endpoint['details']:
                for suite_set in endpoint['details']['suites']:
                    for suite in suite_set['list']:
                        if (not supports_anon_suites and
                                'anon' in suite['name']):
                            supports_anon_suites = True
                        if (not weak_dh and
                                suite.get('kxType', '') == 'DH' and
                                suite.get('kxStrength', 99999) <= 1024):
                            weak_dh = True
                        if (not weak_ciphers and
                                suite.get('cipherStrength', 99999) < 112):
                            weak_ciphers = True

            supports_anon_suites = value_if_graded(
                grade, boolean_to_yes_no(supports_anon_suites))
            weak_dh = value_if_graded(grade, boolean_to_yes_no(weak_dh))
            weak_ciphers = value_if_graded(
                grade, boolean_to_yes_no(weak_ciphers))

            sweet32 = False
            if 'sims' in endpoint['details']:
                for sim in endpoint['details']['sims']['results']:
                    if (not sweet32 and
                            sim.get('protocolId', 0) in [770, 771] and
                            ('IDEA' in sim.get('suiteName', '') or
                             '3DES' in sim.get('suiteName', ''))):
                        sweet32 = True

            sweet32 = value_if_graded(grade, boolean_to_yes_no(sweet32))

            # Determine if site only supports RC4
            rc4_only = value_if_graded(
                grade, boolean_to_yes_no(
                    endpoint['details'].get('rc4Only', False)))

            # Determine if certificate chain is incomplete
            incomplete_chain = False
            for cert_chain in endpoint['details']['certChains']:
                if is_bit_set(cert_chain.get('issues', 0), 1):
                    incomplete_chain = True
                    break

            incomplete_chain = value_if_graded(
                grade, boolean_to_yes_no(incomplete_chain))

            # Determine trust issues
            trust_issues = False
            if grade == 'T':
                trust_issues = True
                grade = grade + '/ ' + endpoint.get('gradeTrustIgnored', '')
            elif grade == 'F' and cert_issues != 0:
                trust_issues = True

            trust_issues = value_if_graded(
                grade, boolean_to_yes_no(trust_issues))

            # Determine user defined grade when SSL Labs fails to scan
            if grade == '':
                if status_message == 'No secure protocols supported':
                    grade = 'No HTTPS'
                elif status_message == 'Unable to connect to the server':
                    # Check if at least one endpoint is secure
                    if (number_of_endpoints > 1 and
                            has_secure_endpoint(ssllabs_json, host)):
                        # Endpoint is probably not accepting traffic
                        grade = 'Could not connect'
                    else:
                        # Check if host can be reached via HTTP
                        if can_connect('http://' + host):
                            grade = 'No HTTPS'
                        else:
                            grade = 'Could not connect'
                else:
                    grade = 'Scan error'

            # Print record
            data_set_values = ['', org, host, ip_address, grade, test_time,
                               status_message, industry, host_purpose,
                               https_behavior, issue_report, heartbleed,
                               openssl_ccs, openssl_lucky_minus20, freak,
                               logjam, poodle_tls, drown_vulnerable,
                               ticketbleed, robot, sslv2, supports_anon_suites,
                               rc4_only, insecure_renegotiation, notls,
                               weak_ciphers, trust_issues, poodle, notlsv12,
                               rc4_with_modern, sweet32, supports_rc4, sslv3,
                               weak_dh, incomplete_chain, weak_private_key,
                               lacks_fs, lacks_aead, lacks_secure_renegotiation]
            print(data_set_values, ',')

            # Update chart data
            update_counts(counts_summary, grade)
            update_counts_by_org(counts_by_org, org, grade)

    # Handle hosts from domains list that were not scanned. Cases:
    # 1. Hosts on ports other than 443 cannot be scanned using SSL Labs
    # 2. SSL Labs sometimes appears to skip records from the input file)
    industry = domains_json.get('industry', '')
    for org_record in domains_json['organizations']:
        org = org_record.get('organization', '')
        for host_record in org_record['hosts']:
            host = host_record.get('host', '')

            https_behavior = host_record.get('httpsBehavior', '')
            if (host == '' or host == '*' or
                    host in hosts_from_ssllabs_report):
                continue

            host_purpose = host_record.get('hostPurpose', '')
            issue_report = host_record.get('issueReport', '')

            # Print record
            data_set_values = ['', org, host, '-', 'Not scanned', '-',
                               'Not scanned', industry, host_purpose,
                               https_behavior, issue_report, '-', '-', '-',
                               '-', '-', '-', '-', '-', '-', '-', '-', '-',
                               '-', '-', '-', '-', '-', '-', '-', '-', '-',
                               '-', '-', '-', '-', '-', '-', '-']
            print(data_set_values, ',')

            # Update chart data
            update_counts(counts_summary, 'Not scanned')
            update_counts_by_org(counts_by_org, org, 'Not scanned')

    # Terminate dataSet
    print('];')

    # Print chart data
    print_chart_data_summary(counts_summary)
    print_chart_data_counts_by_org(counts_by_org)
    print_chart_data_counts_by_org_grade(counts_by_org)


def get_extra_host_data(json_data, host, key):
    """Get additional data from domains JSON."""
    for org_record in json_data['organizations']:
        for host_record in org_record['hosts']:
            if host_record.get('host', '?') in [host, '*']:
                if key == 'organization':
                    return org_record.get('organization', '?')
                return host_record.get(key, '?')

    return '?'


def update_counts(table, key):
    """Update counts for scores by grade."""
    if key in table:
        table[key] = table[key] + 1
    else:
        table[key] = 1
    return table


def update_counts_by_org(table, org, key):
    """Update counts for scores by org by grade."""
    if key.startswith('T/'):
        key = 'T'

    if org in table:
        counts = table[org]
        return update_counts(counts, key)

    counts = {}
    counts[key] = 1
    table[org] = counts
    return table


def value_if_graded(grade, value):
    """Returns value if grade is present."""
    return value if grade != '' else '-'


def boolean_to_yes_no(value):
    """Converts booleans to Yes/ No."""
    return 'Yes' if value else 'No'


def is_bit_set(value, position):
    """Checks if bit is set at a specified position."""
    return value & 2**position != 0


def opensl_ccs_value(value):
    """Value for OpenSSL CCS bug."""
    switcher = {
        -1: 'Test failure',
        0: 'Unknown',
        1: 'No',
        2: 'Possibly',
        3: 'Yes'
    }
    return switcher.get(value, '-')


def openssl_lucky_minus20_value(value):
    """Value for OpenSSL Lucky Minus20 bug."""
    switcher = {
        -1: 'Test failure',
        0: 'Unknown',
        1: 'No',
        2: 'Yes'
    }
    return switcher.get(value, '-')


def ticketbleed_value(value):
    """Value for Ticketbleed bug."""
    switcher = {
        -1: 'Test failure',
        0: 'Unknown',
        1: 'No',
        2: 'Yes'
    }
    return switcher.get(value, '-')


def robot_value(value):
    """Value for ROBOT bug."""
    switcher = {
        -1: 'Test failure',
        0: 'Unknown',
        1: 'No',
        2: 'Yes',
        3: 'Yes',
        4: 'Inconsistent result'
    }
    return switcher.get(value, '-')


def lacks_fs_value(value):
    """Value for Lacks Forward Secrecy flag."""
    return ('Yes' if value in [0, 1]
            else 'No' if value in [2, 4]
            else '')


def poodle_tls_value(value):
    """Value for POODLE TLS bug."""
    switcher = {
        -3: 'Test timeout',
        -2: 'No',
        -1: 'Test failure',
        0: 'Unknown',
        1: 'No',
        2: 'Yes'
    }
    return switcher.get(value, '-')


def has_secure_endpoint(ssllabs_json, host_to_be_checked):
    """Checks if a secure endpoint exists for a host."""
    failures = ['No secure protocols supported',
                'Unable to connect to the server']

    for labs_report in ssllabs_json:
        if labs_report['host'] != host_to_be_checked:
            continue

        if labs_report['status'] != 'READY':
            continue

        for endpoint in labs_report['endpoints']:
            if endpoint.get('statusMessage', '') not in failures:
                return True
        return False


def print_chart_data_counts_by_org(table):
    """Prints chart data by org."""

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
        print('[\'' + org + '\', ' + get_val(counts, 'A+') + ', ' +
              get_val(counts, 'A') + ', ' + get_val(counts, 'A-') + ', ' +
              get_val(counts, 'B') + ', ' + get_val(counts, 'C') + ', ' +
              get_val(counts, 'D') + ', ' + get_val(counts, 'E') + ', ' +
              get_val(counts, 'T') + ', ' + get_val(counts, 'F') + ', ' +
              get_val(counts, 'No HTTPS') + ', ' +
              get_val(counts, 'Scan error') + ', ' +
              get_val(counts, 'Not scanned') + '],')
    print('];')


def print_chart_data_counts_by_org_grade(table):
    """Prints chart data by org and grade."""

    print('var chartDataCountsByOrgAndGrade = {')
    print('labels: [\'{0}\']'.
          format('\', \''.join(str(i) for i in sorted(table.keys()))) + ',')
    print('datasets: [')
    counts_by_org_and_grade = {}
    chart_grades = ['A+', 'A', 'A-', 'B', 'C', 'D', 'E', 'T', 'F', 'No HTTPS',
                    'Scan error', 'Not scanned']
    background_for_grade = {
        'A+': 'rgba(0, 80, 0, 0.9)',
        'A': 'rgba(154, 205, 50, 0.9)',
        'A-': 'rgba(144, 238, 144, 0.9)',
        'B': 'rgba(255, 165, 0, 0.9)',
        'C': 'rgba(255, 165, 0, 0.9)',
        'D': 'rgba(255, 165, 0, 0.9)',
        'E': 'rgba(255, 165, 0, 0.9)',
        'T': 'rgba(255, 0, 0, 0.9)',
        'F': 'rgba(255, 0, 0, 0.9)',
        'No HTTPS': 'rgba(255, 0, 0, 0.9)',
        'Scan error': 'rgba(128, 128, 128, 0.9)',
        'Not scanned': 'rgba(128, 128, 128, 0.9)'
    }
    hover_background_for_grade = {
        'A+': 'rgba(0, 80, 0, 1)',
        'A': 'rgba(154, 205, 50, 1)',
        'A-': 'rgba(144, 238, 144, 1)',
        'B': 'rgba(255, 165, 0, 1)',
        'C': 'rgba(255, 165, 0, 1)',
        'D': 'rgba(255, 165, 0, 1)',
        'E': 'rgba(255, 165, 0, 1)',
        'T': 'rgba(255, 0, 0, 1)',
        'F': 'rgba(255, 0, 0, 1)',
        'No HTTPS': 'rgba(255, 0, 0, 1)',
        'Scan error': 'rgba(128, 128, 128, 1)',
        'Not scanned': 'rgba(128, 128, 128, 1)'
    }

    for grade in chart_grades:
        counts_by_org_and_grade[grade] = []
        for org in sorted(table.keys()):
            counts_by_org_and_grade[grade].append(get_val(table[org], grade))

    for grade in chart_grades:
        print_data_set(grade, background_for_grade[grade],
                       hover_background_for_grade[grade],
                       counts_by_org_and_grade[grade])

    print(']};')


def print_data_set(label, background_color, hover_background_color, data):
    """Prints dataset for chart data by org and grade."""

    print('{')
    print('    label: \'' + label + '\',')
    print('    backgroundColor: \'' + background_color + '\',')
    print('    hoverBackgroundColor: \'' + hover_background_color + '\',')
    print('    borderWidth: 1,')
    print('    borderColor: \'rgb(255, 255, 255)\',')
    print('    data: [{0}]'.format(', '.join(str(i) for i in data)) + ',')
    print('},')


def get_val(table, key):
    """Get string value from table or the text -- null."""

    if key in table:
        return str(table[key])
    return 'null'


def print_chart_data_summary(table):
    """Create dataset for summary chart."""

    print('var chartDataSummary = [')
    print('[\'Grade\', \'Number of sites\', {role: \'style\'}],')

    print_count(table, 'A+', 'A+', ', \'color: Green\'],')
    print_count(table, 'A', 'A', ', \'color: YellowGreen\'],')
    print_count(table, 'A-', 'A-', ', \'color: LightGreen\'],')
    print_count(table, 'B', 'B', ', \'color: Orange\'],')
    print_count(table, 'C', 'C', ', \'color: Orange\'],')
    print_count(table, 'D', 'D', ', \'color: Red\'],')
    print_count(table, 'E', 'E', ', \'color: Red\'],')
    print_count(table, 'T', 'T', ', \'color: Red\'],')
    print_count(table, 'T/ A+', 'T/ A+', ', \'color: Red\'],')
    print_count(table, 'T/ A', 'T/ A', ', \'color: Red\'],')
    print_count(table, 'T/ A-', 'T/ A-', ', \'color: Red\'],')
    print_count(table, 'T/ B', 'T/ B', ', \'color: Red\'],')
    print_count(table, 'T/ C', 'T/ C', ', \'color: Red\'],')
    print_count(table, 'T/ D', 'T/ D', ', \'color: Red\'],')
    print_count(table, 'T/ E', 'T/ E', ', \'color: Red\'],')
    print_count(table, 'T/ F', 'T/ F', ', \'color: Red\'],')
    print_count(table, 'F', 'F', ', \'color: Red\'],')
    print_count(table, 'No HTTPS', 'No HTTPS', ', \'color: Red\'],')
    print_count(table, 'Scan error', 'Scan error', ', \'color: Gray\'],')
    print_count(table, 'Not scanned', 'Not scanned', ', \'color: Gray\'],')
    print_count(table, 'Unknown domain', 'Unknown domain',
                ', \'color: Gray\'],')
    print_count(table, 'Could not connect', 'Could not connect',
                ', \'color: Gray\'],')

    print('];')


def print_count(table, key, print_val, extra):
    """Format dataset for summary chart."""
    if key in table:
        print('[\'' + print_val + '\', ' + str(table[key]) + extra)


def can_connect(url):
    """Check if url is live."""
    try:
        requests.get(url, allow_redirects=False, verify=False, timeout=5)
        return 1
    except:
        return 0


if __name__ == '__main__':
    main(sys.argv[1:])
