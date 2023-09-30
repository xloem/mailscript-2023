#!/usr/bin/env python3
import asyncio, contextlib, ssl

import aioimaplib, aiosmtplib

class Base(contextlib.AbstractAsyncContextManager):
    def __init__(self, user, host, port):
        self.user = user
        self.host = host
        self.port = port
        with open(f'{self.host}:{self.port}.pem') as cafile:
            self._peercert_der = ssl.PEM_cert_to_DER_cert(cafile.read())
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
    
        

class SMTP(Base):
    async def _aenter(self):
        self.client = aiosmtplib.SMTP(
            hostname=self.host,
            port=self.port,
            use_tls=True,
            username=self.user,
            password=self._password(),
            tls_context=self.DUMMY_TLS_CONTEXT,
        )
        await self.client.__aenter__()
        self._verify_tls(self.client.transport)
    async def _aexit(self, params, kwparams):
        await self.client.__aexit__(*params, **kwparams)

class IMAP(Base):
    async def _aenter(self):
        self.client = aioimaplib.IMAP4_SSL(host=self.host,port=self.port,ssl_context=self.DUMMY_TLS_CONTEXT)
        await self.client.wait_hello_from_server()
        self._verify_tls(self.client.protocol.transport)
        await self.client.login(self.user, self._password())
    async def _aexit(self,params,kwparams):
        await self.client.logout()

# okay, send mails, send them on
# maybe smtpd?
    # if we set up an smtpd server we could queue mails and forward them as a batch.
    # and keep using our normal mail interface for similarity, if desired.

async def amain():
    async with (
        SMTP('mailbombbin', 'smtp.gmail.com', 465) as smtp,
        IMAP('mailbombbin', 'imap.gmail.com', 993) as imap,
    ):
        res, data = await imap.client.select()
        print(f'INBOX: {data[3]}')

if __name__ == '__main__':
    asyncio.run(amain())
