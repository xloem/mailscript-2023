#!/usr/bin/env python3
import asyncio, contextlib, ssl, logging, warnings
logging.basicConfig(level=logging.DEBUG)

import aioimaplib, aiosmtplib, aiosmtpd, email
import aiosmtpd.controller, aiosmtpd.smtp, email.message

import asyncio

class SMTPServer(contextlib.AbstractAsyncContextManager):
    def __init__(self, host, port):
        self.host = host
        self.port = port

    async def __aenter__(self):
        tls = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        tls.load_cert_chain(f'{self.host}.pem', f'{self.host}.key')
        warnings.warn('errors output by aiosmtpd SMTP() constructor could be hidden')
        self.aio_controller = aiosmtpd.controller.UnthreadedController( # runs in same thread
        #self.sync_controller = aiosmtpd.controller.Controller( # runs in dedicated thread
            self,
            loop = asyncio.get_running_loop(),
            hostname = self.host,
            port = self.port,
            #ssl_context = tls,
            tls_context = tls,
            authenticator = (
                lambda server, session, envelope, mechanism, auth_data: 
                    aiosmtpd.smtp.AuthResult(success=True)
            ),
        )
        self.aio_controller.server_coro = self.aio_controller._create_server()
        self.aio_controller.server = await self.aio_controller.server_coro
        #await asyncio.to_thread(self.sync_controller.start)
        return await super().__aenter__()

    async def __aexit__(self, *params, **kwparams):
        await self.aio_controller.finalize()
        #self.aio_controller.cancel_tasks(stop_loop=False)
        #await asyncio.to_thread(self.sync_controller.stop)
        return await super().__aexit__(*params, **kwparams)
    
    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        if not address.endswith('@example.com'):
            return '550 not relaying to that domain'
        envelope.rcpt_tos.append(address)
        return '250 OK'

    async def handle_DATA(self, server, session, envelope):
        print('Message from %s' % envelope.mail_from)
        print('Message for %s' % envelope.rcpt_tos)
        print('Message data:\n')
        for ln in envelope.content.decode('utf8', errors='replace').splitlines():
            print(f'> {ln}'.strip())
        print()
        print('End of message')
        return '250 Message accepted for delivery'

class BaseClient(contextlib.AbstractAsyncContextManager):
    def __init__(self, user, host, port):
        self.user = user
        self.host = host
        self.port = port
        with open(f'{self.host}.pem') as cafile:
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
    
        

class SMTPClient(BaseClient):
    async def _aenter(self):
        self.client = aiosmtplib.SMTP(
            hostname=self.host,
            port=self.port,
            #use_tls=True,
            start_tls=True,
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
        await self.client.send_message(message)
    async def _aexit(self, params, kwparams):
        await self.client.__aexit__(*params, **kwparams)

class IMAPClient(BaseClient):
    async def _aenter(self):
        self.client = aioimaplib.IMAP4_SSL(host=self.host,port=self.port,ssl_context=self.DUMMY_TLS_CONTEXT)
        await self.client.wait_hello_from_server()
        import pdb; pdb.set_trace()
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
        SMTPServer('localhost', 10465) as smtpserver,
        SMTPClient('mailbombbin', smtpserver.host, smtpserver.port) as smtpclient,
        #SMTPClient('mailbombbin', 'smtp.gmail.com', 465) as smtpclient,
        #IMAPClient('mailbombbin', 'imap.gmail.com', 993) as imapclient,
    ):
        await smtpclient.send('user@example.com', 'hello', 'hi user this is a test message')
        #await asyncio.sleep(60*60)
        pass
        #res, data = await imapclient.client.select()
        #print(f'INBOX: {data[3]}')

if __name__ == '__main__':
    asyncio.run(amain())
