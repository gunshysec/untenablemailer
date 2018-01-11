import os
import requests
import time
import sys
import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate

REPORT_TYPE_DEFAULT = {"format": "pdf", "chapters": "vuln_hosts_summary"}
REPORT_TYPE_BY_PLUGIN = {"format": "pdf","chapters": "vuln_by_plugin;remediations"}
#Add more of these if you need them
REPORTS = [
    {
        'group': 'GroupNameHere',
        'type': REPORT_TYPE_BY_PLUGIN,
        'scans': [
            'ScanNameHere',
            'ScanNameHere'
        ]
        'email': [
            'whotosendto@domain.com',
            'otherperson@domain.com'
        ]
    },

    {
        'group': 'GroupNameHere',
        'scans': [
            'ScanNameHere',
            'ScanNameHere'
        ]
        'email': [
            'whotosendto@domain.com',
            'otherperson@domain.com'
        ]
        
    }
]
#You will need to make individual folders corresponding to your group names
REPORT_BASE_DIR = '/Where/You/Store/Things'

os.environ['HTTPS_PROXY'] = 'http://if-you-need-a-proxy.com:8080'

ACCESS_KEY = sys.argv[1]
SECRET_KEY = sys.argv[2]

HEADERS = {'X-ApiKeys': 'accessKey=' + ACCESS_KEY + '; secretKey=' + SECRET_KEY}
NESSUS_BASE_URL = "https://cloud.tenable.com"

def DownloadReport(scanID, filename, reportType):
    req = requests.post('%s/scans/%s/export' % (NESSUS_BASE_URL, scanID), json=reportType, headers=HEADERS)
    response = req.json()
    if 'error' in response:
        print('\nFailed to get report:')
        print(response)
        return

    fileID = str(response['file'])
    while True:
        print('.', end='', flush=True)
        time.sleep(1)
        req = requests.get(NESSUS_BASE_URL + '/scans/' + scanID + '/export/' + fileID + '/status', headers=HEADERS)
        if req.json()['status'] == 'ready':
            break

    req = requests.get(NESSUS_BASE_URL + '/scans/' + scanID + '/export/' + fileID + '/download', headers=HEADERS)

    f = open(filename, 'wb')
    f.write(req.content)
    f.close()

    print('done')

def send_mail(send_from, send_to, subject, text, files=None, server=''):
    assert isinstance(send_to, list)

    msg = MIMEMultipart()
    msg['From'] = send_from
    msg['To'] = COMMASPACE.join(send_to)
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject

    msg.attach(MIMEText(text))

    for f in files or []:
        with open(f, "rb") as fil:
            part = MIMEApplication(
                fil.read(),
                Name=os.path.basename(f)
            )
        part['Content-Disposition'] = 'attachment; filename="%s"' % os.path.basename(f)
        msg.attach(part)


    smtp = smtplib.SMTP(server)
    smtp.sendmail(send_from, send_to, msg.as_string())
    smtp.close()


def GetScanIDs():
    scanIDs = {}
    req = requests.get(NESSUS_BASE_URL + '/scans', headers=HEADERS)
    data = req.json()
    for scan in data['scans']:
        scanIDs[scan['name']] = str(scan['id'])

    return scanIDs


def GetVulnerabilityCounts(scanID):
    data = requests.get(NESSUS_BASE_URL + '/scans/' + scanID, headers=HEADERS).json()
    crits = highs = meds = 0
    for host in data['hosts']:
        crits += host['critical']
        highs += host['high']
        meds += host['medium']

    return crits, highs, meds


def main():
    scanIDs = GetScanIDs()
    for report in REPORTS:
        criticals = highs = mediums = 0
        print('Gathering reports for', report['group'])
        reportType = report.get('type', REPORT_TYPE_DEFAULT)
        filenames = []
        for scanname in report['scans']:
            filename = REPORT_BASE_DIR + os.sep + report['group'] + os.sep + scanname + '.pdf'
            filenames.append(filename)
            if scanname not in scanIDs.keys():
                print('Could not find a scan ID for that group!')
                continue
            print('Saving report for', scanname, 'scan ID', scanIDs[scanname], 'to', filename, end='', flush=True)
            scanCriticals, scanHighs, scanMediums = GetVulnerabilityCounts(scanIDs[scanname])
            criticals += scanCriticals
            highs += scanHighs
            mediums += scanMediums
            DownloadReport(scanIDs[scanname], filename, reportType)


        print('Vulnerability counts for group', report['group'])
        print('Criticals:', criticals)
        print('Highs:', highs)
        print('Mediums:', mediums)

        subject = 'Nessus Scan Results'
        body = 'Here is your most recent Nessus scan results'

        send_mail('from@domain.com', report['email'], subject, body, filenames, 'smtp.yourdomain.com')

if __name__ == '__main__':
    main()
