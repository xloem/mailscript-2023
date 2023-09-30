import asyncio, contextlib, hashlib, ssl

import aiohttp, aioimaplib, aiosmtplib, ar, email # ar == git+https://github.com/xloem/pyarweave
import bundlr, email.message

class BaseClient(contextlib.AbstractAsyncContextManager):
    def __init__(self, user, host, port):
        self.user = user
        self.host = host
        self.port = port
        self._peercert_fn = f'{self.host}.pem'
        with open(self._peercert_fn) as cafile:
            self._peercert_der = ssl.PEM_cert_to_DER_cert(cafile.read())
        self._peercert_sha256 = hashlib.sha256(self._peercert_der).hexdigest()
    def _password(self):
        with open(f'{self.user}.password') as pwdfile:
            return pwdfile.read().strip()
    def _verify_tls(self, transport):
        peercert_der = transport._ssl_protocol._extra['ssl_object'].getpeercert(True)
        assert self._peercert_der == peercert_der
        self.cert_verified = True
    async def __aenter__(self):
        await self._aenter()
        return await super().__aenter__()
    async def __aexit__(self, *params, **kwparams):
        await self._aexit(params, kwparams)
        return await super().__aexit__(*params, **kwparams)   
    DUMMY_TLS_CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    DUMMY_TLS_CONTEXT.check_hostname = False
    DUMMY_TLS_CONTEXT.verify_mode = ssl.CERT_NONE
    
        

class SMTPClient(BaseClient):
    def __init__(self, user, host, port, starttls=None):
        super().__init__(user, host, port)
        self.starttls = starttls if starttls is not None else port == 587
    async def _aenter(self):
        self.client = aiosmtplib.SMTP(
            hostname=self.host,
            port=self.port,
            use_tls=not self.starttls,
            start_tls=self.starttls,
            username=self.user,
            password=self._password(),
            tls_context=self.DUMMY_TLS_CONTEXT,
        )
        await self.client.__aenter__()
        #if not self.client.get_transport_info("sslcontext"):
        #    await self.client.starttls()
        self._verify_tls(self.client.transport)
    async def send(self, to, subject, body):
        message = email.message.EmailMessage()
        message['From'] = f'{self.user}@{self.host}'
        message['To'] = to
        message['Subject'] = subject
        message.set_content(body)
        return await self.client.send_message(message)
    async def send_raw(self, recipients, raw):
        return await self.client.sendmail(
            f'{self.user}@{self.host}',
            recipients,
            raw,
        )
    async def _aexit(self, params, kwparams):
        await self.client.__aexit__(*params, **kwparams)

class IMAPClient(BaseClient):
    async def _aenter(self):
        self.client = aioimaplib.IMAP4_SSL(host=self.host,port=self.port,ssl_context=self.DUMMY_TLS_CONTEXT)
        await self.client.wait_hello_from_server()
        self._verify_tls(self.client.protocol.transport)
        await self.client.login(self.user, self._password())
    async def _aexit(self,params,kwparams):
        await self.client.logout()

class BundlrClient(BaseClient):
    async def _aenter(self):
        self.wallet = ar.Wallet(f'{self.user}.wallet')
        self.node = bundlr.Node(f'https://{self.host}:{self.port}', cert_fingerprint=self._peercert_sha256)

    async def send(self, data, *tags, **kwtags):
        di = ar.DataItem(
            data = data,
            header = ar.ANS104DataItemHeader(
                tags = [
                    {
                        'name': key.encode(),
                        'value': val.encode(),
                    }
                    for key, val in list(tags) + list(kwtags.items())
                ]
            ),
        )
        di.sign(self.wallet.rsa)
        result = await asyncio.to_thread(self.node.send_tx, di.tobytes())
        txid = result['id']
        assert txid == di.header.id
        return result # id, timestamp
        
    async def _aexit(self, params, kwparams):
        del self.node
        del self.wallet
        
    #def _get_gateways(self):
        # ['gateways'] id/props
        # 'status': 'joined'
            # 'settings': {protocol://fqdn:port  label, note, properties==id?}
