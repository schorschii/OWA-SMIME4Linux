#!/bin/python3

from pathlib import Path
import queue
import quopri
import subprocess
import traceback
import atexit
import struct
import json
import random, string
import sys, os

from M2Crypto import BIO, Rand, SMIME, X509, EVP
from OpenSSL import crypto
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend

LOGFILE = 'native.log'
SMIME_PROTOCOL_NAMESPACE = ':#Microsoft.Exchange.Clients.BrowserExtension.Smime'
SMIME_CONTROL_NAMESPACE  = ':#Microsoft.Exchange.Clients.Smime'
SMIME_CONTROL_VERSION    = '4.0700.19.19.814.1'

def log(text):
    if(LOGFILE):
        with open(LOGFILE, 'a') as logfile:
            logfile.write(text+"\n\n")

def decrypt_smime(smime_content):
    header = 'Content-Type: application/x-pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"\n\n'
    smime_message = bytes(header + smime_content, encoding='utf-8')

    cert_path = str(Path.home())+'/.config/owa-smime4linux/cert.pem'
    if(not os.path.isfile(cert_path)):
        raise Exception(cert_path+' does not exist!')

    proc = subprocess.Popen(
        ['openssl', 'smime', '-decrypt', '-recip', cert_path],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE
    )
    decrypted = proc.communicate(input=smime_message)[0]

    tmpFilePathSigner = '/tmp/signer.pem'
    proc = subprocess.Popen(
        ['openssl', 'smime', '-verify', '-signer', tmpFilePathSigner],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.PIPE
    )
    verified = proc.communicate(input=decrypted)[0]

    signer_cert = ''
    with open(tmpFilePathSigner, 'r') as f:
        signer_cert = f.read()
    return verified.decode(), signer_cert

def parse_multipart_body(body):
    lines = body.replace("\r\n", "\n").strip().split("\n", 1)
    if(not lines[0].lower().startswith('content-type: multipart')):
        return body
    boundary = None
    for item in lines[0].split(';'):
        if(item.strip().lower().startswith('boundary=')):
            boundary = item.strip()[9:].strip('"')
    text_plain = ''
    for part in lines[1].split(boundary):
        part_parts = part.replace("\r\n", "\n").strip().split("\n\n", 1)
        if(len(part_parts) != 2): continue
        part_headers = part_parts[0]
        part_body = part_parts[1]
        part_body_type = 'text/plain'
        part_body_encoding = None
        for header in part_headers.split("\n"):
            header_parts = header.split(':')
            if(header_parts[0].lower() == 'content-type'):
                part_body_type = header_parts[1].split(';')[0].strip().lower()
            elif(header_parts[0].lower() == 'content-transfer-encoding'):
                if(header_parts[1].split(';')[0].strip().lower() == 'quoted-printable'):
                    part_body = quopri.decodestring(part_parts[1]).decode('utf-8')
        if(part_body_type == 'text/html'):
            return part_body, 'HTML'
        else:
            text_plain = part_body
    return text_plain, 'TEXT'

def handle_owa_message(message):
    msg = json.loads(message)
    log('>> ' + str(msg))

    inner_data_response = handle_partial_data(
        msg['data']['__type'],
        msg['data']['PartialData'] if 'PartialData' in msg['data'] else '{}'
    )
    if(inner_data_response):
        rsp = {
            "data": inner_data_response,
            "messageType": msg['messageType'],
            "portId": msg['portId'],
            "requestId": msg['requestId']
        }
        send_native_message(json.dumps(rsp))

fetch_partial_data = json.dumps({
    "Data": {
        "__type": "SmimeControlCapabilities"+SMIME_CONTROL_NAMESPACE,
        "SupportsAsyncMethods": True,
        "Version": SMIME_CONTROL_VERSION
    },
    "ErrorCode": 0
})
def handle_partial_data(type, message):
    global fetch_partial_data
    msg = json.loads(message)
    #log('>>> ' + str(msg))

    if(type == 'PostPartialSmimeRequest'+SMIME_PROTOCOL_NAMESPACE):
        # OWA hello message
        if(msg['__type'] == 'InitializeParams'+SMIME_PROTOCOL_NAMESPACE):
            return {
                "__type": "AcknowledgePartialSmimeRequestArrived"+SMIME_PROTOCOL_NAMESPACE,
                "PartIndex": -1,
                "StartOffset": -1,
                "NextStartOffset": -1,
                "Status": 1
            }

        # request to decrypt a SMIME message
        if(msg['__type'] == 'CreateMessageFromSmimeParams'+SMIME_PROTOCOL_NAMESPACE):
            smime_content = msg['Smime'].strip()
            if(len(msg['Smime'].split(',')) > 1):
                smime_content = msg['Smime'].split(',')[1]#.replace("\r\n", "\n").replace("\n", "").strip()
            decrypted, signer_cert = decrypt_smime(smime_content)
            body, body_type = parse_multipart_body(decrypted)

            cert = x509.load_pem_x509_certificate(signer_cert.encode('ascii'), default_backend())
            signer_cert = (signer_cert.strip()
                .lstrip('-----BEGIN CERTIFICATE-----')
                .rstrip('-----END CERTIFICATE-----')
                .replace("\r\n", "\n").replace("\n", ""))

            fetch_partial_data = json.dumps({
                "Data": {
                    "__type": "Message:#Exchange",
                    "Attachments": None,
                    "Body": None,
                    "CcRecipients": None,
                    "Classification": None,
                    "ClassificationDescription": None,
                    "ClassificationGuid": None,
                    "ClassificationKeep": False,
                    "DateTimeSent": None,
                    "From": None,
                    "HasAttachments": False,
                    "Importance": None,
                    "InReplyTo": None,
                    "IsClassified": False,
                    "IsDeliveryReceiptRequested": False,
                    "IsReadReceiptRequested": False,
                    "ItemClass": "IPM.Note.SMIME",
                    "ItemId": {
                        "Id": "smime-" + ''.join(random.choices(string.ascii_lowercase + string.digits, k=32)),
                        "__type": "ItemId:#Exchange"
                    },
                    "NormalizedBody": {
                        "BodyType": body_type,
                        "Value": body,
                        "__type": "BodyContentType:#Exchange"
                    },
                    "NormalizedSubject": None,
                    "RawDate": None,
                    "Sender": None,
                    "Sensitivity": None,
                    "SmimeSignature": {
                        "CertIssuedBy": str(cert.issuer.rfc4514_string()),
                        "CertIssuedTo": str(cert.subject.rfc4514_string()),
                        "CertRawData": signer_cert,
                        "CertValidFrom": str(cert.not_valid_before),
                        "CertValidTo": str(cert.not_valid_after),
                        "ClientVerificationResult": 0,
                        "IsCertValidToClient": True,
                        "IsCertValidToServer": False,
                        "IsHashMatched": True,
                        "ServerVerificationResult": -1,
                    },
                    "SmimeType": 13,
                    "Subject": None,
                    "ToRecipients": None,
                    "__type": "Message:#Exchange"
                },
                "ErrorCode": 0
            })
            return {
                "__type": "AcknowledgePartialSmimeRequestArrived"+SMIME_PROTOCOL_NAMESPACE,
                "PartIndex": -1,
                "StartOffset": -1,
                "NextStartOffset": -1,
                "Status": 1
            }

    # request to return decrypted SMIME message
    if(type == 'FetchPartialSmimeResult'+SMIME_PROTOCOL_NAMESPACE):
        return {
            "__type": "ReturnPartialSmimeResult"+SMIME_PROTOCOL_NAMESPACE,
            "PartIndex": 0,
            "StartOffset": 0,
            "EndOffset": len(fetch_partial_data),
            "IsLastPart": True,
            "PartialData": fetch_partial_data,
            "TotalSize": len(fetch_partial_data)
        }

def send_native_message(msg):
    log('<< ' + str(msg))
    sys.stdout.buffer.write(struct.pack('I', len(msg)))
    if(isinstance(msg, str)):
        sys.stdout.buffer.write(msg.encode('utf-8'))
    else:
        sys.stdout.buffer.write(msg)
    sys.stdout.flush()

def recv_native_message(queue):
    message_number = 0
    while True:
        # read the message length (first 4 bytes)
        text_length_bytes = sys.stdin.buffer.read(4)
        if(len(text_length_bytes) == 0):
            if(queue): queue.put(None)
            sys.exit(0)
        else:
            # unpack message length as 4 byte integer
            text_length = struct.unpack('i', text_length_bytes)[0]
            # read the text (JSON object) of the message
            text = sys.stdin.buffer.read(text_length).decode('utf-8')
            if(queue): queue.put(text)
            handle_owa_message(text)

def exit_log():
    log('[EXIT]')
atexit.register(exit_log)

def main():
    try:
        # On Windows, the default I/O mode is O_TEXT. Set this to O_BINARY
        # to avoid unwanted modifications of the input/output streams.
        # (For personal reference only for future Native Messaging apps.)
        #if(sys.platform == 'win32'):
        #    import os, msvcrt
        #    msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        #    msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)

        recv_native_message(None)
    except Exception as e:
        log(str(traceback.format_exc()))

if(__name__ == '__main__'):
    main()
