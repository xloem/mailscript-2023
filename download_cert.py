import ssl
import sys

for host in sys.argv[1:]:
    cert = ssl.get_server_certificate(host.split(':'))
    assert cert
    with open(f'{host.split(":")[0]}.pem', 'w') as f:
        f.write(cert)
