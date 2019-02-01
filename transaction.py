
import wallet
import hashlib

class Transaction:

    def __init__(self, amount, sender, recipient):
        self.amount = amount
        self.sender = sender # pub_key
        self.recipient = recipient #addr
        self.raw_tx = self.amount + self.sender + self.recipient
        self.sha_tx = None

    def calculation(self):
        self.sha_tx = hashlib.sha256(bytes(self.raw_tx.encode('utf-8'))).hexdigest()


class CoinbaseTransaction(Transaction):
    var = None
    ##TODO
