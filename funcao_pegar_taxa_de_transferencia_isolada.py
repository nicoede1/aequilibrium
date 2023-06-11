import http.client as httplib

def server_status(url):
    cn = httplib.HTTPConnection(url)
    cn.request("GET", "/server-status?auto")
    resp = cn.getresponse()
    if resp.status != 200:
        cn.close()
        raise ValueError('HTTP %s recebida de %s.' % (resp.status, url))
    raw = resp.read()
    cn.close()

    eita = raw.splitlines()
    tput = str(eita[21]).split(': ')[1]
    tput = tput.split("'")[0]
    return float(tput)

throughput_1 = server_status('10.10.1.2')
throughput_2 = server_status('10.10.1.3')

print("tput 2: ", throughput_1)
print("tput 3: ", throughput_2)
