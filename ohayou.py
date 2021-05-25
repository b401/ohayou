import httpx
import OpenSSL
import contextlib
import json
import sys
import asyncio
import threading
import dns.resolver
import ssl,socket
from datetime import datetime
from cryptography import x509

# sudo docker run -it --rm --name test -v /mnt/files_test:/tmp/a -w /tmp/a ohayou:latest python /usr/src/app/ohayou.py /tmp/a/$i

reqhandler = httpx.AsyncClient(verify=False)
reqhandler.timeout=1.0

loop = asyncio.get_event_loop()

global dq
dq = asyncio.queues.Queue()

class DomainWorker:
    def __init__(self,domain):
        self.domain = domain
        self.ip = dns_resolver(self.domain)
        self.loop = loop
        self.connection = {
            "https": False,
            "http": False,
        }
        self.flags = {
            "domain" : self.domain,
            "ip": self.ip,
            "time_of_req": str(datetime.now()),
            "robots" : {},
            "svn" : {},
            "git" : {},
            "certificate": [{
                "san": [],
                "expired": False,
                "subject": None,
                "until": None,
                "issuer": None,
            }],
            'https_banner': [{
                'server': None,
                'content-type': None,
                'date': None,
                'x-xss-protection': None,
                'content-security-policy': None,
                'content-origin-embedder-policy': None,
                'cross-origin-opener-policy': None,
                'cross-origin-resource-policy': None,
             }],        
            'http_banner':[ {
                'server':None,
                'content-type': None,
                'date': None,
                'x-xss-protection': None,
                'content-security-policy': None,
                'content-origin-embedder-policy': None,
                'cross-origin-opener-policy': None,
                'cross-origin-resource-policy': None,
             }]
        }

    async def check_connection(self) -> None:
        for contype in ['http','https']:
            try:
                await reqhandler.get(f"{contype}://{self.domain}/")
                self.connection[contype] = True
            except:
                self.connection[contype] = False
                pass

    async def check_robots(self):
        self.flags["robots"] = await self.get("robots.txt")

    async def check_svn_dir(self):
        r = await self.get(".svn/wc.db", grab = True)
        self.flags["svn"] = self.check_helper(r,"SQLite")

    async def check_git_dir(self):
        r = await self.get(".git/HEAD", grab = True)
        self.flags["git"] = self.check_helper(r,"ref: refs/heads/")

    def check_helper(self,response,searchfor):
        proto = {"http": False, "https": False}
        for i in response:
            if not isinstance(response[i], bool) and response[i].status_code == 200:
                if response[i].content.startswith(searchfor.encode()):
                    proto[i] = True

        return proto
    
    # https://github.com/securitytxt/security-txt
    async def check_security_text(self):
      r = await self.get(".well-known/security.txt",grab=True)
      self.flags["security.txt"] = self.check_helper(r,"Contact")

    async def grab_banner(self):
        # http or https 
        banner_proto = await self.get(grab=True)
        for i in banner_proto:
            if not isinstance(banner_proto[i], bool):
                for j in self.flags[f"{i}_banner"]:
                    for attributes in j:
                        if attributes in banner_proto[i].headers:
                            self.flags[f"{i}_banner"][0][attributes] = banner_proto[i].headers[attributes]
            else:
                del(self.flags[f"{i}_banner"])

    # https://stackoverflow.com/questions/30862099/how-can-i-get-certificate-issuer-information-in-python
    def check_ssl_hostname(self):
        print(f"checking https {self.domain}")
        if self.connection["https"] == False:
            del(self.flags["certificate"])
            print("nothin httpsfucking off")
            return

        # SEE COMMIT: https://github.com/python/cpython/commit/49fdf118aeda891401d638ac32296c7d55d54678
        # Available with python 3.10
        #cert_all = ssl.get_server_certificate((self.domain, 443), self.domain)
        try:
            cert_all = ssl.get_server_certificate((self.domain, 443))
            cert = x509.load_pem_x509_certificate(cert_all.encode())
        except:
            return
        self.flags['certificate'][0]['subject'] = cert.subject.rfc4514_string()
        try:
            for i in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName):
                self.flags['certificate'][0]['san'].append(i)
        except:
                self.flags['certificate'][0]['san'].append(None)
            

        self.flags['certificate'][0]['until'] = str(cert.not_valid_after)
        self.flags['certificate'][0]['issued_to'] = cert.subject.rdns[0].rfc4514_string()
        self.flags['certificate'][0]['issuer'] = cert.issuer.rfc4514_string()
        if cert.not_valid_after < datetime.strptime(self.flags["time_of_req"], "%Y-%m-%d %H:%M:%S.%f"):
            self.flags['certificate'][0]['expired'] = True

        return
            
        
    async def get(self,folder="",grab=False):
        state = {'http': False, 'https': False}
        if grab == True:
            for proto in state:
                try:
                    if self.connection[proto]:
                        state[proto] = await reqhandler.get(f"{proto}://{self.domain}/{folder}")
                except:
                    pass
        else: 
            for proto in state:
                try:
                    if self.connection[proto]:
                        r = await reqhandler.get(f"{proto}://{self.domain}/{folder}")
                        if r.status_code == 200:
                            state[proto] = True
                except:
                    pass

        return state
        
    
    async def run(self):
        if self.ip == None:
            return
        await self.check_connection()
        if True not in self.connection.values():
            return
        td = threading.Thread(target=self.check_ssl_hostname)
        td.start()
        await asyncio.gather(
            self.check_robots(),
            self.check_svn_dir(),
            self.check_git_dir(),
            self.check_security_text(),
            self.grab_banner()
        )
        print(f"awaiting for domain {self.domain}")
        td.join()
        dq.put_nowait(self.flags)
            

async def get_all_queue_items(q,filehandler):
    print("alright everything here.")
    items = []
    while True:
        try:
            items.append(q.get_nowait())
        except asyncio.QueueEmpty:
            print("saving to file.")
            json.dump(items,filehandler,indent=4)
            break

def dns_resolver(domain):
    resolver = dns.resolver.Resolver()
    try:
        answer = resolver.resolve(domain, "A")
    except:
        return None
    return str(answer[0])



async def close_reqhandler():
    await reqhandler.aclose()


async def worker(name,queue):
    while True:
        item = await queue.get()
        print(f"[#] Working on {item}")
        await DomainWorker(item).run()
        print(f"[#] done {item}")
        queue.task_done()

async def main():

    input_file = sys.argv[1]
    output_file = input_file + "_done.json"
    tasks = []
    queuesize = 100
    queue = asyncio.queues.Queue(maxsize=queuesize)
    start = datetime.now()
    print("[x] Starting execution at: {}".format(start))
    with open(input_file, 'r') as domainlist:
        with open(output_file, "a+") as fh:
            for domain in domainlist:
                # Fill queue until full
                try:
                    queue.put_nowait(domain.strip())
                except asyncio.QueueFull:
                    # Create x amount of worker tasks
                    for i in range(50):
                        asyncio.create_task(worker(f"Worker-{i}",queue))
                        task = asyncio.create_task(worker(f"Worker-{i}",queue))
                        tasks.append(task)
                    await queue.join()
                    print("queue is done")
                    for task in tasks:
                        task.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)
                    await get_all_queue_items(dq,fh)

            # ugly hack # fix later (maybe?)
            for i in range(queue.qsize()):
                asyncio.create_task(worker(f"Worker-{i}",queue))
                task = asyncio.create_task(worker(f"Worker-{i}",queue))
                tasks.append(task)
            await queue.join()
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await get_all_queue_items(dq,fh)
    await close_reqhandler()
    end = datetime.now()
    print("Ending execution at: {}".format(end))
    diff = end-start
    print("Diff: {}".format(diff.total_seconds()))




asyncio.run(main())
