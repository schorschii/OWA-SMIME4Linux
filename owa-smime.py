#!/bin/python3

from pathlib import Path
import queue
import quopri
import subprocess
import traceback
import atexit
import struct
import json
import base64
import random, string
import sys, os

from cryptography import x509
from cryptography.hazmat.backends import default_backend

LOGFILE = 'native.log' # use None for no logging

SMIME_PROTOCOL_NAMESPACE = ':#Microsoft.Exchange.Clients.BrowserExtension.Smime'
SMIME_CONTROL_NAMESPACE  = ':#Microsoft.Exchange.Clients.Smime'
SMIME_CONTROL_VERSION    = '4.0700.19.19.814.1'


def log(text):
    if(LOGFILE):
        with open(LOGFILE, 'a') as logfile:
            logfile.write(text+"\n\n")

def decrypt_smime(smime_content):
    header = ''
    if(not smime_content.lower().startswith('content-type:')):
        header = 'Content-Type: application/x-pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"\n\n'
    smime_message = bytes(header + smime_content, encoding='utf-8')

    cert_path = str(Path.home())+'/.config/owa-smime4linux/cert.pem'
    if(not os.path.isfile(cert_path)):
        raise Exception(cert_path+' does not exist!')

    proc = subprocess.Popen(
        ['openssl', 'cms', '-decrypt', '-recip', cert_path],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE
    )
    output = proc.communicate(input=smime_message)
    strError = output[1].decode('utf-8')
    if(strError.strip() != ''):
        log('!!! OpenSSL stderr: ' + strError)

    return output[0].decode()

def verify_smime(smime_content, noverify=False):
    if(not isinstance(smime_content, bytes)):
        smime_content = bytes(smime_content, encoding='utf-8')

    tmpFilePathSigner = '/tmp/signer.pem'
    if(os.path.isfile(tmpFilePathSigner)):
        os.unlink(tmpFilePathSigner)

    proc = subprocess.Popen(
        ['openssl', 'smime', '-verify', '-signer', tmpFilePathSigner, '-noverify' if noverify else ''],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE
    )
    output = proc.communicate(input=smime_content)
    strError = output[1].decode('utf-8')
    if(strError.strip() != ''):
        log('!!!x OpenSSL stderr: ' + strError)

    if(proc.returncode != 0):
        return verify_smime(smime_content, True)

    signer_cert = ''
    if(os.path.isfile(tmpFilePathSigner)):
        with open(tmpFilePathSigner, 'r') as f:
            signer_cert = f.read()
    return output[0].decode(), signer_cert, not noverify

def parse_multipart_body(body):
    # get the multipart boundary
    lines = body.replace("\r\n", "\n").strip().split("\n")
    found_multipart = False
    boundary = None
    line = 0
    while True:
        if(not lines[line].startswith(' ') and not lines[line].startswith('\t')):
            found_multipart = False
        for item in lines[line].split(';'):
            if(item.strip().lower().startswith('content-type: multipart')):
                found_multipart = True
            if(found_multipart and item.strip().lower().startswith('boundary=')):
                boundary = item.strip()[9:].strip('"')
                line = None
        # content-type header with boundary may be broken into multiple lines
        if(line == None): break
        line += 1

    # fallback - return unparsed body if message was not detected as multipart
    if(not found_multipart or boundary == None):
        return body, 'TEXT'

    # iterate over multiparts and return HTML if avail, TEXT as fallback
    text_plain = ''
    for part in body.split(boundary):
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
                elif(header_parts[1].split(';')[0].strip().lower() == 'base64'):
                    part_body = base64.b64decode(part_parts[1]).decode('utf-8')
        if(part_body_type.startswith('multipart')):
            # parse nested multipart - we love recursion
            return parse_multipart_body(part)
        elif(part_body_type == 'text/html'):
            return part_body, 'HTML'
        elif(part_body.strip() != ''):
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

        # request to parse a SMIME message
        if(msg['__type'] == 'CreateMessageFromSmimeParams'+SMIME_PROTOCOL_NAMESPACE):
            smime_content = msg['Smime'].strip()
            if(len(msg['Smime'].split(',')) > 1):
                payload = msg['Smime'].split(',')
                smime_content_type = payload[0]
                smime_content = payload[1].replace("\r\n", "\n").strip()

            # decrypt and verify
            if(smime_content_type.startswith('data:application/pkcs7-mime')
            or smime_content_type.startswith('data:application/x-pkcs7-mime')):
                decrypted = decrypt_smime(smime_content)
                verified, signer_cert, signature_valid = verify_smime(decrypted)
            # verify only
            elif(smime_content_type.startswith('data:multipart/signed')):
                verified, signer_cert, signature_valid = verify_smime(base64.b64decode(smime_content))
            else:
                raise Exception('Unknown content type: '+smime_content_type)

            # get message body
            body, body_type = parse_multipart_body(verified)

            # get signer cert
            certIssuedBy = ''
            certIssuedTo = ''
            certValidFrom = ''
            certValidTo = ''
            try:
                cert = x509.load_pem_x509_certificate(signer_cert.encode('ascii'), default_backend())
                certIssuedBy = str(cert.issuer.rfc4514_string())
                certIssuedTo = str(cert.subject.rfc4514_string())
                certValidFrom = str(cert.not_valid_before)
                certValidTo = str(cert.not_valid_after)
                signer_cert = (signer_cert.strip()
                    .lstrip('-----BEGIN CERTIFICATE-----')
                    .rstrip('-----END CERTIFICATE-----')
                    .replace("\r\n", "\n").replace("\n", ""))
            except Exception as e:
                log('!!! Unable to parse signer cert: '+str(e))

            # prepare response to OWA
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
                        "CertIssuedBy": certIssuedBy,
                        "CertIssuedTo": certIssuedTo,
                        "CertRawData": signer_cert,
                        "CertValidFrom": certValidFrom,
                        "CertValidTo": certValidTo,
                        "ClientVerificationResult": 0,
                        "IsCertValidToClient": signature_valid,
                        "IsCertValidToServer": False,
                        "IsHashMatched": signature_valid,
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
