import httplib

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
    load = float(eita[19].split(': ')[1])
    tput = float(eita[22].split(': ')[1])
    return load, tput

load_1, throughput_1 = server_status('10.10.1.2')
load_2, throughput_2 = server_status('10.10.1.3')

print("tput 2: ", throughput_1)
print("load 2: ", load_1)
print("tput 3: ", throughput_2)
print("load 3: ", load_2)