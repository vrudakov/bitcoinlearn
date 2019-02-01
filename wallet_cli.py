import wallet
import cmd
import os
os.chdir(os.getcwd())
from transaction import Transaction

class WrongArgs(Exception):
    pass


class AmountError(Exception):
    pass

def wif_checksum(wif):
    byte_str = wallet.b58decode(wif)
    byte_str_drop_last_4bytes = byte_str[0:-8]
    sha_256_1 = wallet.sha256(byte_str_drop_last_4bytes)
    sha_256_2 = wallet.sha256(sha_256_1)
    first_4_bytes = sha_256_2[0:8]
    last_4_bytes_wif = byte_str[-8:]
    bytes_check = False
    if first_4_bytes == last_4_bytes_wif : bytes_check = True
    check_sum = False
    if bytes_check and byte_str[0:2] == "80": check_sum = True
    return check_sum


def wif_to_priv(wif):
    if not wif_checksum(wif): raise Exception('The WIF is not correct (does not pass checksum)')
    byte_str = wallet.b58decode(wif)
    byte_str_drop_last_4bytes = byte_str[0:-8]
    byte_str_drop_first_byte = byte_str_drop_last_4bytes[2:]
    return byte_str_drop_first_byte

class WalletCli(cmd.Cmd):
    intro = "CLI made large strokes. Light version 0.1"
    prompt = "wallet_cli: "

    def do_new(self, line):
        private_key = wallet.gen_privkey(line)
        print("your private key: " + private_key)
        public_key = wallet.get_public(private_key)
        print("your public: " + public_key)
        f = open("key.txt", "w+")
        f.write(public_key)
        f.close()


    def do_import(self, line):
        if line == '':
            print("usage: ")
            return False
        try:
            f = open(line, "r")
            key = f.read()
        except:
            print("No such file or directory:" + line)
            return False
        if key is None:
            return False
        priv_key = wif_to_priv(key)
        if priv_key is None:
            return False
        print("Your private key: " + priv_key)
        f = open("key.txt", "w+")
        f.write(wallet.get_public(priv_key))
        f.close()

    def do_send(self, line):
        try:
            lines = str(line).split()
            if len(lines) != 2:
                raise WrongArgs
            recipient = str(lines[0])
            amount = int(lines[1])
            if amount > 65535 or amount < 1:
                raise AmountError
            pitoshi = format(amount, 'x')
            f = open("key.txt", "r")
            sender = f.read()
            print(sender)
            tx = Transaction(pitoshi, sender, recipient)
            tx.calculation()
            # TODO validator
            # Serialze

        except WrongArgs:
            print("Wrong send arguments")
            return False
        except AmountError:
            print("We are limited to 4 bytes.The amount should be from 0.1 to 6553.5")
            return False


if __name__ == '__main__':
    WalletCli().cmdloop()