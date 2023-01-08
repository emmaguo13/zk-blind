import hashlib
import rsa
import argparse
import os
import base64

def verifyJWT(header, payload, sig, pub_key):

    # sig = "mLCysHQtDftfFey4F-ntFma22r5-qpxtkXsiDw6TY30Tnoj2kPQ_YdSjzagrwRgF7pHE8SSM_roo2wDh3c_8vDNRZeax4VICZjYmPS-3ZWAV0XyjjlgWgFleTqVT72M-VlPCdecHiYQJojlYHJyGybvTCaX1cqoF9aAMy8wBvRbSceECmX15k4nKG51Z5Le7k_vOShaxYmwrRhMIip4KRv-DW1FXAdi_F-MYSrqZ6Oq-nglMujxD2NOoHoqOqmyd1OMIrc6oIRuRqBXlRnQ0IdUDQbiXfyFVC0ItIME3a4SLoWp_rrmY1tSrGJu93MZrjhzfkNglJ-FOp4kKZAKkzA"
    # generate the sha256 hash of the encoded header and payload
    message = header + "." + payload
    message = message.encode()
    hashed_msg = hashlib.sha256()
    hashed_msg.update(message)
    print("hashed message")
    print(hashed_msg)
    # encoded_msg = hashed_msg.encode()

    with open(pub_key, 'rb') as f:
        pk = f.read()
    print(pk)

    # verify with signature and message
    rsa_pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(keyfile=pk)
    print("rsa pubkey")
    print(rsa_pubkey)
    print("SIG")
    print(sig)

    signature_bytes = base64.urlsafe_b64decode(sig + '=' * (4 - len(sig) % 4))

    res = rsa.verify(message, signature_bytes, rsa_pubkey)
    print("verified result")
    print(res)


def main():
    banner = """
██████╗ ███████╗██████╗ ███████╗ ██████╗     ██████╗     ██╗  ██╗███████╗██████╗ ███████╗ ██████╗
██╔══██╗██╔════╝╚════██╗██╔════╝██╔════╝     ╚════██╗    ██║  ██║██╔════╝╚════██╗██╔════╝██╔════╝
██████╔╝███████╗ █████╔╝███████╗███████╗      █████╔╝    ███████║███████╗ █████╔╝███████╗███████╗
██╔══██╗╚════██║██╔═══╝ ╚════██║██╔═══██╗    ██╔═══╝     ██╔══██║╚════██║██╔═══╝ ╚════██║██╔═══██╗
██║  ██║███████║███████╗███████║╚██████╔╝    ███████╗    ██║  ██║███████║███████╗███████║╚██████╔╝
╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝ ╚═════╝     ╚══════╝    ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝ ╚═════╝
                                                                                      By: 3v4Si0N
"""
    helpbanner = """
###############################################
    Tool for JWT attack algorithm
    RS256 to HS256
    Requisit:
        - You have to know the public key
###############################################
"""
    parser = argparse.ArgumentParser()
    # header, payload, sig, pub_key
    parser.add_argument('header', help='encoded header')
    parser.add_argument('payload', help='encoded payload')
    parser.add_argument('sig', help='signature')
    # pem of the pubkey
    parser.add_argument('pub_key', help='pubkey')

    args = parser.parse_args()

    # if (args.payload and args.pub_key and args.header and args.sig):
    if (args.payload and args.header and args.sig):
        payload = args.payload
        header = args.header 
        sig = args.sig 
        pub_key = args.pub_key
        
        verifyJWT(header, payload, sig, pub_key)

main()