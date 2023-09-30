#!/usr/bin/env python3
import json
import ar

with open('arweave.wallet', 'w') as file:
    wallet = ar.Wallet.generate()
    json.dump(wallet.jwk_data, file)
