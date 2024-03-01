# OWA-SMIME4Linux
This is a Linux implementation of the Outlook Web App SMIME control for Linux. Originally, SMIME functionality in OWA is only available for Windows.

OWA uses [Native Messaging](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging) to communicate with a small piece of software installed on the user's computer to do SMIME mail de-/encryption. The browser hands the SMIME ciphertext to this software which decrypts it using the certificate from the local cert store, and returns it to the website so that the plaintext can be displayed (or vice versa when sending encrypted mails).

Native Messaging can only be initiated by a browser extension, that's why beside the locally installed SMIME handler, a browser extension is necessary. This Linux implementation works flawlessly with the original "Microsoft S/MIME" extension for Chrome, so there is no special or modified extension needed. Note that this browser extension is only [compatible with Chrome/Chromium](https://learn.microsoft.com/en-us/exchange/policy-and-compliance/smime/smime-settings-for-owa?view=exchserver-2019) (and IE + Edge, but they do not apply to Linux).

OWA-SMIME4Linux internally calls the `openssl` command line utility for de-/encrypting and verifying the email payload.

## Installation
1. Install dependencies: `apt install openssl python3-cryptography`
2. Copy `owa-smime.py` into `/usr/bin/` and make it executable.
3. Register the OWA-SMIME4Linux Native Messaging app by copying `com.microsoft.outlook.smime.chromenativeapp.json` into:
   - `/etc/opt/chrome/native-messaging-hosts/` for Chrome
   - `/etc/chromium/native-messaging-hosts/` for Chromium
   - (`/usr/lib/mozilla/native-messaging-hosts/` for Firefox, if supported in the future)
4. Install the "Microsoft S/MIME" extension in your Chrome browser.
   - The extension is currently not available in the normal Chrome web store. As suggested on the [Microsoft documentation](https://learn.microsoft.com/en-us/exchange/policy-and-compliance/smime/smime-settings-for-owa?view=exchserver-2019), you should use the Chrome policy "ExtensionInstallForcelist" to deploy it.
   - For testing purposes, you can also open the link `https://outlook.office.com/owa/SmimeCrxUpdate.ashx` from the MS docs, then follow the "codebase" URL to `https://res-1.cdn.office.net/owasmime/<VERSION>/Microsoft.Outlook.Smime.crx`, download and drag&drop the .crx archive into the Chrome extension page (dev mode must be enabled).
   - On-Prem Exchange only: open the "Microsoft S/MIME" extension settings page and enter your domain name to make the extension trust your domain.
5. Put your cert with private key in PEM format into `~/.config/owa-smime4linux/cert.pem` and the cert chain into `~/.config/owa-smime4linux/chain.pem`. The chain will be included in signatures.  
   You can use the following commands to convert a .p12/.pfx file into .pem.  
   Remember to restrict access permissions to this folder.  
   - `openssl pkcs12 -in cert.p12 -out cert.pem -nodes -legacy`
   - `openssl pkcs12 -in cert.p12 -out chain.pem -nodes -cacerts -nokeys -chain -legacy`

## Usage
First, if you are still logged in, log out and log in again. OWA checks the SMIME control availability when logging in.

1. Open a SMIME encrypted and/or signed mail -> profit.
2. Sending a SMIME encrypted and/or signed mail unfortunately needs one more hack. Thanks to Microsoft, the encrypt/signing options only appear if the browser's user agent contains "Windows". You need to open the dev tools (F12), click on the 3 dots -> More Tools -> Network Conditions. There, disable "Use browser default" and select "Chrome - Windows". Log out and log in again, now you shoud have the options to enable encryption/signing when writing an email. This is only a temporary workaround. If you have a better solution please let me know!

## Debugging
In case of problems, you can create an empty file `~/.cache/owa-smime4linux/native.log` to enable logging of the Native Messaging communication. Attention: this will contain decrypted messages in plaintext. Delete the file afterwards to disable logging!

## Interesting OpenSSL Commands
- `openssl smime -in mymail.eml -verify -noverify -signer scert.pem -out textdata`
- `cat message.eml | openssl smime -pk7out | openssl pkcs7 -print_certs`
- `openssl pkcs7 -in signature.p7 -inform DER -print_certs`
