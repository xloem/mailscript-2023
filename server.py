#!/usr/bin/env python3
import asyncio, contextlib, queue, ssl#, logging, warnings
#logging.basicConfig(level=logging.DEBUG)

import aiosmtpd, email
import aiosmtpd.controller, aiosmtpd.smtp

from client import SMTPClient, BundlrClient

class SMTPServer(contextlib.AbstractAsyncContextManager):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.queue = queue.Queue()

    async def __aenter__(self):
        tls = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        tls.load_cert_chain(f'{self.host}.pem', f'{self.host}.key')
        #warnings.warn('errors output by aiosmtpd SMTP() constructor could be hidden') # still true
        #self.aio_controller = aiosmtpd.controller.UnthreadedController(self, loop=asyncio.get_running_loop() # runs in same thread
        self.sync_controller = aiosmtpd.controller.Controller(self, # runs in dedicated thread
            hostname = self.host,
            port = self.port,
            #ssl_context = tls,
            tls_context = tls,
            authenticator = (
                lambda server, session, envelope, mechanism, auth_data: 
                    aiosmtpd.smtp.AuthResult(success=True)
            ),
        )
        #self.aio_controller.server_coro = self.aio_controller._create_server()
        #self.aio_controller.server = await self.aio_controller.server_coro
        await asyncio.to_thread(self.sync_controller.start)
        return await super().__aenter__()

    async def __aexit__(self, *params, **kwparams):
        #await self.aio_controller.finalize()
        ##self.aio_controller.cancel_tasks(stop_loop=False)
        await asyncio.to_thread(self.sync_controller.stop)
        return await super().__aexit__(*params, **kwparams)

    def __len__(self):
        return len(self.queue)

    def __iter__(self):
        while True:
            items = [self.queue.get()]
            for idx in range(self.queue.qsize()):
                items.append(self.queue.get())
            yield items

    async def __aiter__(self):
        while True:
            items = [await asyncio.to_thread(self.queue.get)]
            for idx in range(self.queue.qsize()):
                items.append(self.queue.get_nowait())
            yield items
    
    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        #if not address.endswith('@example.com'):
        #    return '550 not relaying to that domain'
        envelope.rcpt_tos.append(address)
        return '250 OK'

    async def handle_DATA(self, server, session, envelope):
        self.queue.put([server, session, envelope])
        #print('Message from %s' % envelope.mail_from)
        #print('Message for %s' % envelope.rcpt_tos)
        #print('Message data:\n')
        #for ln in envelope.content.decode('utf8', errors='replace').splitlines():
        #    print(f'> {ln}'.strip())
        #print()
        #print('End of message')
        return '250 Message accepted for delivery'

async def process_mail(bundlrclient, smtpclient, server, session, envelope):
    message = email.message_from_bytes(envelope.content)
    orig_headers = message._headers
    extra_headers = [
    #    ['From', envelope.mail_from],
    #] + [
    #    ['To', to]
    #    for to in envelope.rcpt_tos
    ##] + [
        ['ar-bundlr-node', bundlrclient.node.api_url],
        ['ar-bundlr-cert-sha256', bundlrclient._peercert_sha256],
    ]
    message._headers = [
        message.policy.header_store_parse(k, v)
        for k, v in extra_headers
    ] + orig_headers
    bundle = await bundlrclient.send(envelope.content, *message.items())
    for key, val in bundle.items():
        extra_headers.append([f'ar-bundlr-{key}', str(val)])
    message._headers = [
        message.policy.header_store_parse(k, v)
        for k, v in extra_headers
    ] + orig_headers
    payload = message.get_payload(decode=True)
    if type(payload) is str:
        payload += f'\nar-bundlr-id: {bundle["id"]}\n'
    elif type(payload) is bytes:
        payload += f'\nar-bundlr-id: {bundle["id"]}\n'.encode()
    else:
        payload.append('\nar-bundlr-id: {bundle["id"]}\n')
    message.set_payload(payload)
    content = bytes(message)
    await smtpclient.send_raw(envelope.rcpt_tos, content)
    # envelope.content
    print('Message from %s' % envelope.mail_from)
    print('Message for %s' % envelope.rcpt_tos)
    for name, value in message.items():
        print(f'Message {name}: {value}')
    print('Message data:\n')
    for ln in content.decode('utf8', errors='replace').splitlines():
        print(f'> {ln}'.strip())
    print()
    print('End of message')
    # return None for convenience below

async def amain():
    async with (
        SMTPServer('localhost', 10465) as smtpserver,
        SMTPClient('mailbombbin', smtpserver.host, smtpserver.port, starttls=True) as local_smtpclient,
        SMTPClient('mailbombbin', 'smtp.gmail.com', 587) as smtpclient,
        BundlrClient('arweave', 'node2.bundlr.network', 443) as bundlrclient,
        #IMAPClient('mailbombbin', 'imap.gmail.com', 993) as imapclient,
    ):
        await local_smtpclient.send('user@example.com', 'hello', 'hi user this is a test message')
        tasks = []
        async for mails in smtpserver:
            await asyncio.gather(*[
                process_mail(bundlrclient, smtpclient, server, session, envelope)
                for server, session, envelope in mails
            ])
        #res, data = await imapclient.client.select()
        #print(f'INBOX: {data[3]}')

if __name__ == '__main__':
    asyncio.run(amain())
