#!/usr/bin/env python3
"""Exercise patched functions with real OpenSSL and disposable certificates."""
import ast
import os
from pathlib import Path
import subprocess
import tempfile

source_path = Path(__file__).with_name('owa-smime.py')
tree = ast.parse(source_path.read_text())
names = {'decrypt_smime', 'sign_smime', 'guessEncodingAndDecode', 'DecryptionException'}
subset = ast.Module(body=[node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names], type_ignores=[])
namespace = {'os': os, 'subprocess': subprocess}
exec(compile(subset, str(source_path), 'exec'), namespace)

def run(*args, data=None):
    return subprocess.run(args, input=data, capture_output=True, check=True).stdout

with tempfile.TemporaryDirectory() as work:
    directory = Path(work)
    pairs = []
    for name in ('current', 'old1', 'old2', 'unknown'):
        key, cert, pem = [directory / (name + suffix) for suffix in ('.key', '.crt', '.pem')]
        run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=' + name, '-keyout', str(key), '-out', str(cert))
        pem.write_bytes(cert.read_bytes() + key.read_bytes())
        pairs.append((key, cert, pem))
    content = b'Content-Type: text/plain\r\n\r\nHistorical mail test.\r\n'
    messages = [run('openssl', 'cms', '-encrypt', '-aes256', str(cert), data=content).decode() for key, cert, pem in pairs]
    # OWA supplies the base64 CMS payload rather than a complete RFC822 message.
    messages = [message.split('\n\n', 1)[1] for message in messages]
    config = {'key-id': None, 'private-key': str(pairs[0][2]), 'cert-chain': None,
              'decryption-keys': [str(directory/'missing.pem'), str(pairs[1][2]), str(pairs[2][2])]}
    namespace['jsonConfig'] = config
    decrypt = namespace['decrypt_smime']
    for i in range(3):
        assert decrypt(messages[i]).encode() == content
    print('PASS: active key and two historical keys, including missing-file fallback')
    for message in (messages[3], 'malformed encrypted message'):
        try:
            decrypt(message)
        except namespace['DecryptionException']:
            pass
        else:
            raise AssertionError('Decryption should fail')
    print('PASS: unknown recipient and malformed content fail without plaintext')
    # An encrypted PEM must not block fallback by prompting for a password.
    protected = directory/'protected.pem'
    encrypted_key = run('openssl', 'pkey', '-in', str(pairs[1][0]), '-aes256', '-passout', 'pass:test')
    protected.write_bytes(pairs[1][1].read_bytes() + encrypted_key)
    config['decryption-keys'].insert(0, str(protected))
    assert decrypt(messages[2]).encode() == content
    print('PASS: unusable encrypted key does not block remaining keys')
    namespace['get_temp_path'] = lambda name: str(directory/name)
    namespace['log'] = lambda message: None
    signature = namespace['sign_smime'](content, pairs[0][1].read_text())
    signer = directory/'actual-signer.pem'
    verified = run('openssl', 'smime', '-verify', '-noverify', '-signer', str(signer), data=signature.encode())
    assert verified == content
    assert run('openssl', 'x509', '-in', str(signer), '-outform', 'DER') == run('openssl', 'x509', '-in', str(pairs[0][1]), '-outform', 'DER')
    print('PASS: signing still uses only the current certificate and key')
    del config['decryption-keys']
    assert decrypt(messages[0]).encode() == content
    print('PASS: existing single-key configuration remains compatible')
