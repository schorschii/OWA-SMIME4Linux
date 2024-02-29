#!/bin/python3

from datetime import datetime
from pathlib import Path
import copy
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
from cryptography.hazmat.primitives.serialization import Encoding

SMIME_PROTOCOL_NAMESPACE = ':#Microsoft.Exchange.Clients.BrowserExtension.Smime'
SMIME_CONTROL_NAMESPACE  = ':#Microsoft.Exchange.Clients.Smime'
SMIME_CONTROL_VERSION    = '4.0700.19.19.814.1'

MAX_DOWNLOAD_MESSAGE_SIZE = 100000


config_path = str(Path.home())+'/.config/owa-smime4linux'
def get_cert_path():
    Path(config_path).mkdir(parents=True, exist_ok=True)
    os.chmod(config_path, 0o700)
    cert_path = config_path+'/cert.pem'
    if(not os.path.isfile(cert_path)):
        raise Exception(cert_path+' does not exist!')
    return cert_path

cache_files = []
cache_path = str(Path.home())+'/.cache/owa-smime4linux'
def get_temp_path(filename):
    Path(cache_path).mkdir(parents=True, exist_ok=True)
    os.chmod(cache_path, 0o700)
    signer_path = cache_path+'/'+filename
    if(os.path.isfile(signer_path)):
        os.unlink(signer_path)
    if(not signer_path in cache_files):
        cache_files.append(signer_path)
    return signer_path

def log(text):
    Path(cache_path).mkdir(parents=True, exist_ok=True)
    os.chmod(cache_path, 0o700)
    log_path = cache_path+'/'+'native.log'
    if(os.path.isfile(log_path)):
        with open(log_path, 'a') as log_file:
            log_file.write(text+"\n\n")

def decrypt_smime(smime_content):
    header = ''
    if(not smime_content.lower().startswith('content-type:')):
        header = 'Content-Type: application/x-pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"\n\n'
    smime_message = bytes(header + smime_content, encoding='utf-8')

    proc = subprocess.Popen(
        ['openssl', 'cms', '-decrypt', '-recip', get_cert_path()],
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

    tmp_path_signer = get_temp_path('signer.pem')
    proc = subprocess.Popen(
        ['openssl', 'smime', '-verify', '-signer', tmp_path_signer, '-noverify' if noverify else ''],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE
    )
    output = proc.communicate(input=smime_content)
    strError = output[1].decode('utf-8')
    if(strError.strip() != ''):
        log('!!! OpenSSL stderr: ' + strError)

    if(proc.returncode != 0):
        return verify_smime(smime_content, True)

    signer_cert = ''
    if(os.path.isfile(tmp_path_signer)):
        with open(tmp_path_signer, 'r') as f:
            signer_cert = f.read()
    return output[0].decode(), signer_cert, not noverify

def encrypt_smime(content, recipient_certs):
    if(not isinstance(content, bytes)):
        content = bytes(content, encoding='utf-8')

    tmp_path_recipients = get_temp_path('recipients.pem')
    with open(tmp_path_recipients, 'w') as f:
        for recipient_cert in recipient_certs:
            f.write(recipient_cert)

    proc = subprocess.Popen(
        ['openssl', 'smime', '-encrypt', tmp_path_recipients],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE
    )
    output = proc.communicate(input=content)
    strError = output[1].decode('utf-8')
    if(strError.strip() != ''):
        log('!!! OpenSSL stderr: ' + strError)

    if(proc.returncode != 0):
        raise Exception('OpenSSL encrypt error, return code '+str(proc.returncode))

    return output[0].decode()

def sign_smime(content, signature_cert):
    if(not isinstance(content, bytes)):
        content = bytes(content, encoding='utf-8')

    tmp_path_signer = get_temp_path('signer.pem')
    with open(tmp_path_signer, 'w') as f:
        f.write(signature_cert)

    proc = subprocess.Popen(
        ['openssl', 'smime', '-sign', '-signer', tmp_path_signer, '-inkey', get_cert_path()],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE
    )
    output = proc.communicate(input=content)
    strError = output[1].decode('utf-8')
    if(strError.strip() != ''):
        log('!!! OpenSSL stderr: ' + strError)

    if(proc.returncode != 0):
        raise Exception('OpenSSL sign error, return code '+str(proc.returncode))

    return output[0].decode()

# recycling: a well-known function from the OCO-Agent, reused to save the environment
def guessEncodingAndDecode(textBytes, codecs=['utf-8', 'cp1252', 'cp850']):
    if(isinstance(textBytes, str)):
        return textBytes
    for codec in codecs:
        try:
            return textBytes.decode(codec)
        except UnicodeDecodeError: pass
    return textBytes.decode(sys.stdout.encoding, 'replace') # fallback: replace invalid characters

def parse_body(part):
    part_parts = part.strip().split("\n\n", 1)
    if(len(part_parts) == 1): return '', 'FAIL'
    part_headers = part_parts[0]
    part_body = part_parts[1]
    part_type = ''
    for header, fields in parse_headers(part_headers).items():
        if(header.lower() == 'content-type'):
            part_type = fields[0].lower()
        elif(header.lower() == 'content-transfer-encoding'):
            if(fields[0].lower() == 'quoted-printable'):
                part_body = quopri.decodestring(part_parts[1])
            elif(fields[0].lower() == 'base64'):
                part_body = base64.b64decode(part_parts[1])
    if(part_type == 'text/html' and part_body.strip() != ''):
        return guessEncodingAndDecode(part_body), 'HTML'
    elif(part_type.startswith('text/') and part_body.strip() != ''):
        return guessEncodingAndDecode(part_body), 'TEXT'
    else:
        return part_body, 'BIN'

def parse_headers(part):
    header_block = part.strip().split("\n\n", 1)[0]
    # condense headers with line breaks back into one line
    header_block = header_block.replace("\n ", "").replace("\n\t", "")
    # parse headers into a dict
    headers = {}
    for line in header_block.split("\n"):
        header_parts = line.split(':', 1)
        if(len(header_parts) == 1): continue
        headers[header_parts[0].strip()] = [s.strip() for s in header_parts[1].split(';')]
    return headers

def parse_multipart_body(body):
    body_return_candidate = (body, 'TEXT')
    attachments = []

    # normalize line endings
    body = body.replace("\r\n", "\n")

    # get the multipart boundary for further parsing
    # or return body directly if it isn't a multipart message
    boundary = None
    for header, fields in parse_headers(body).items():
        if(header.lower() == 'content-type'):
            if(fields[0].lower() == 'text/plain' or fields[0].lower() == 'text/html'):
                body_return_candidate = parse_body(body)
            elif(fields[0].lower().startswith('multipart')):
                for field in fields:
                    if(field.lower().startswith('boundary=')):
                        boundary = field[9:].strip('"')

    # fallback - not a multipart message
    if(boundary == None):
        return body_return_candidate[0], body_return_candidate[1], attachments

    # split by boundary and iterate over multiparts
    inner_multipart = body.split('--'+boundary+'--')[0]
    inner_multiparts = inner_multipart.split('--'+boundary)
    inner_multiparts.pop(0) # avoid endless loop - do not parse ourself again
    for part in inner_multiparts:
        part_type = 'text/plain'
        filename = None
        for header, fields in parse_headers(part).items():
            if(header.lower() == 'content-disposition' and fields[0].lower() == 'attachment'):
                for field in fields:
                    if(field.lower().startswith('filename=')):
                        filename = field[9:].strip('"')
            if(header.lower() == 'content-type'):
                part_type = fields[0].lower()
        if(part_type.startswith('multipart')):
            # parse nested multipart - we love recursion
            body_return_candidate = parse_multipart_body(part)
        elif(filename):
            # decode and append attachment
            payload, payload_type = parse_body(part)
            attachments.append({'name': filename, 'type': part_type, 'content': payload})
        else:
            # decode the message body
            payload, payload_type = parse_body(part)
            # return HTML if avail
            if(payload_type == 'HTML'):
                body_return_candidate = (payload, payload_type)
            # save TEXT for fallback return if no HTML part was found
            elif(payload_type == 'TEXT' and body_return_candidate[1] == 'TEXT'):
                body_return_candidate = (payload, 'TEXT')

    return body_return_candidate[0], body_return_candidate[1], attachments

def generate_id():
    return 'smime-' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=32))

waiting_snake = {}
def handle_owa_message(message):
    msg = json.loads(message)

    shortlog = True
    if(shortlog):
        logmsg = copy.deepcopy(msg)
        if('PartialData' in logmsg['data']):
            logmsg['data']['PartialData'] = logmsg['data']['PartialData'][:250]
        log('>> ' + str(logmsg))
    else:
        log('>> ' + str(msg))

    if(msg['messageType'] == 'GetSettings'):
        send_native_message(json.dumps({
            "AllowedDomainsByPolicy": []
        }))
        return

    if(msg['requestId'] in waiting_snake
    and 'PartialData' in waiting_snake[msg['requestId']]['data']
    and 'PartialData' in msg['data']):
        # append next packet to partial request
        waiting_snake[msg['requestId']]['data']['PartialData'] += msg['data']['PartialData']
        waiting_snake[msg['requestId']]['Recv-PartIndex'] += 1
    else:
        # store request in queue, keep PartIndex
        prev_values = {'Recv-PartIndex': 0, 'Send-PartIndex': 0}
        if(msg['requestId'] in waiting_snake):
            prev_values['Recv-PartIndex'] = waiting_snake[msg['requestId']]['Recv-PartIndex']
            prev_values['Send-PartIndex'] = waiting_snake[msg['requestId']]['Send-PartIndex']
        waiting_snake[msg['requestId']] = msg
        waiting_snake[msg['requestId']]['Recv-PartIndex'] = prev_values['Recv-PartIndex']
        waiting_snake[msg['requestId']]['Send-PartIndex'] = prev_values['Send-PartIndex']

    if(msg['messageType'] == 'UploadPartialRequest'):
        if(msg['data']['IsLastPart']):
            # transfer complete - process request before acknowledging last part
            # this implementation is not really async capable as advertised in the initialization message, but cui bono? :))
            inner_data_response = handle_partial_data(
                waiting_snake[msg['requestId']]['data']['__type'],
                waiting_snake[msg['requestId']]['data']['PartialData'] if 'PartialData' in waiting_snake[msg['requestId']]['data'] else '{}'
            )
        # acknowledge incoming data
        rsp = {
            "data": {
                "__type": "AcknowledgePartialSmimeRequestArrived"+SMIME_PROTOCOL_NAMESPACE,
                "PartIndex":       -1 if msg['data']['IsLastPart'] else waiting_snake[msg['requestId']]['Recv-PartIndex'],
                "StartOffset":     -1 if msg['data']['IsLastPart'] else msg['data']['StartOffset'],
                "NextStartOffset": -1 if msg['data']['IsLastPart'] else (msg['data']['StartOffset']+len(msg['data']['PartialData'])),
                "Status":           1 if msg['data']['IsLastPart'] else 0
            },
            "messageType": waiting_snake[msg['requestId']]['messageType'],
            "portId":      waiting_snake[msg['requestId']]['portId'],
            "requestId":   waiting_snake[msg['requestId']]['requestId']
        }
        send_native_message(json.dumps(rsp))

    elif(msg['messageType'] == 'DownloadPartialResult'):
        # send processing result
        start_offset = waiting_snake[msg['requestId']]['Send-PartIndex'] * MAX_DOWNLOAD_MESSAGE_SIZE
        end_offset   = (waiting_snake[msg['requestId']]['Send-PartIndex']+1) * MAX_DOWNLOAD_MESSAGE_SIZE
        is_last_part = end_offset >= len(fetch_partial_data)
        rsp = {
            "data": {
                "__type": "ReturnPartialSmimeResult"+SMIME_PROTOCOL_NAMESPACE,
                "PartIndex":   waiting_snake[msg['requestId']]['Send-PartIndex'],
                "StartOffset": start_offset,
                "EndOffset":   end_offset,
                "IsLastPart":  is_last_part,
                "PartialData": fetch_partial_data[start_offset:end_offset],
                "TotalSize":   len(fetch_partial_data)
            },
            "messageType": waiting_snake[msg['requestId']]['messageType'],
            "portId":      waiting_snake[msg['requestId']]['portId'],
            "requestId":   waiting_snake[msg['requestId']]['requestId']
        }
        waiting_snake[msg['requestId']]['Send-PartIndex'] += 1
        send_native_message(json.dumps(rsp))

    else:
        log('!!! Oh no, I don\'t know how to handle this request :(')

fetch_partial_data = ''
def handle_partial_data(type, message):
    global fetch_partial_data
    msg = json.loads(message)
    #log('>>> ' + str(msg))

    if(not '__type' in msg):
        return

    if(type == 'PostPartialSmimeRequest'+SMIME_PROTOCOL_NAMESPACE):
        # OWA hello message, respond with our version
        if(msg['__type'] == 'InitializeParams'+SMIME_PROTOCOL_NAMESPACE):
            fetch_partial_data = json.dumps({
                "Data": {
                    "__type": "SmimeControlCapabilities"+SMIME_CONTROL_NAMESPACE,
                    "SupportsAsyncMethods": True,
                    "Version": SMIME_CONTROL_VERSION
                },
                "ErrorCode": 0
            })

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

            # log plaintext message for debugging
            #with open(get_temp_path('message.txt'), 'w') as f:
            #    f.write(verified)

            # get message body
            body, body_type, body_attachments = parse_multipart_body(verified)

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
            attachments = []
            for attachment in body_attachments:
                attachments.append({
                    "__type":"FileAttachment:#Exchange",
                    "AttachmentId": {"Id":generate_id(), "__type":"AttachmentId:#Exchange"},
                    "ContentId": "",
                    "ContentLocation": None,
                    "ContentType": attachment['type'],
                    "IsInline": False,
                    "IsSmimeDecoded": True,
                    "Name": attachment['name'],
                    "Size": len(attachment['content']),
                    "Content": base64.b64encode(attachment['content']).decode('utf-8')
                })
            fetch_partial_data = json.dumps({
                "Data": {
                    "__type": "Message:#Exchange",
                    "HasAttachments": len(attachments)>0,
                    "Attachments": attachments if len(attachments)>0 else None,
                    "Body": None,
                    "CcRecipients": None,
                    "Classification": None,
                    "ClassificationDescription": None,
                    "ClassificationGuid": None,
                    "ClassificationKeep": False,
                    "DateTimeSent": None,
                    "From": None,
                    "Importance": None,
                    "InReplyTo": None,
                    "IsClassified": False,
                    "IsDeliveryReceiptRequested": False,
                    "IsReadReceiptRequested": False,
                    "ItemClass": "IPM.Note.SMIME",
                    "ItemId": {
                        "Id": generate_id(),
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
                    "SmimeType": 13, # who knows
                    "Subject": None,
                    "ToRecipients": None,
                    "__type": "Message:#Exchange"
                },
                "ErrorCode": 0
            })

        # request to return signing cert
        if(msg['__type'] == 'GetSigningCertificateParams'+SMIME_PROTOCOL_NAMESPACE):
            with open(get_cert_path(), 'rb') as f:
                cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                fetch_partial_data = json.dumps({
                    "Data": base64.b64encode(cert.public_bytes(Encoding.DER)).decode('utf-8'),
                    "ErrorCode": 0
                })

        # request to create a SMIME message
        if(msg['__type'] == 'CreateSmimeFromMessageParams'+SMIME_PROTOCOL_NAMESPACE):
            email_message = json.loads(msg['EmailMessage'])
            recipients = []
            for recipient in email_message['ToRecipients']:
                recipients.append('"'+recipient['Name']+'" <'+recipient['EmailAddress']+'>')
            signing_cert = None
            if(msg['SigningCertificate']):
                signing_cert = (
                    '-----BEGIN CERTIFICATE-----\n'+msg['SigningCertificate']+'\n-----END CERTIFICATE-----\n'
                )
            encryption_certs = []
            if(msg['EncryptionCertificates']):
                for raw_cert in json.loads(msg['EncryptionCertificates']):
                    encryption_certs.append(
                        '-----BEGIN CERTIFICATE-----\n'+raw_cert+'\n-----END CERTIFICATE-----\n'
                    )

            signed = sign_smime(
                'Content-Type: text/html'+"\r\n\r\n"+email_message['Body']['Value'],
                signing_cert
            )
            encrypted = encrypt_smime(signed, encryption_certs)

            headers = [
                'MIME-Version: 1.0',
                'From: "'+email_message['From']['Mailbox']['Name']+'" <'+email_message['From']['Mailbox']['EmailAddress']+'>',
                'To: '+', '.join(recipients),
                'Subject: '+(email_message['Subject'] if 'Subject' in email_message else '?'),
                'Importance: '+(email_message['Importance'] if 'Importance' in email_message else 'Normal'),
                'Sensitivity: '+(email_message['Sensitivity'] if 'Sensitivity' in email_message else 'Normal'),
                'Date: '+datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z'),
                'X-Generated-By: OWA-SMIME4Linux '+SMIME_CONTROL_VERSION,
                'Content-Type: application/x-pkcs7-mime; name="smime.p7m"; smime-type="enveloped-data"',
                'Content-Transfer-Encoding: base64',
                'Content-Disposition: attachment; filename="smime.p7m"'
            ]
            #log("\r\n".join(headers)+"\r\n\r\n"+encrypted.replace("\n", "\r\n").split("\r\n\r\n", 1)[1])
            fetch_partial_data = json.dumps({
                "Data": ("\r\n".join(headers)
                    +"\r\n\r\n"
                    +encrypted.replace("\n", "\r\n").split("\r\n\r\n", 1)[1]
                )
            })

def send_native_message(msg):
    shortlog = True
    if(shortlog):
        logmsg = copy.deepcopy(msg)[:250]
        log('<< ' + str(logmsg))
    else:
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
    for file_path in cache_files:
        if(os.path.isfile(file_path)):
            os.unlink(file_path)
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
