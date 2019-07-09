# threema-keybackup-tool
Since this is just a small script I wrote for learning purposes, it isn't probably very user friendly, yet.
However, for someone with coding background it should be easy to use.

## Installation
Just create a new virtual environment and install the dependencies via `pip install -r requirements.txt`.

## Usage
To check your key password and/or extract the internal information (like the unencrypted private key,...) execute the following steps against `decrypt.py`:

1. Specify (backup) code  
   Enter your (backup-)key by replacing `<insert your backup key here>` with your actual backup key in the form of a 80 character base32 encoded string, which is grouped by several dashes.

   Example: `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`
   
   You get it e.g. by creating a key backup via the app and decoding the QR-Code.

2. Specify the password
   Enter the password which is protecting your key (or which you want to test against your key) by replacing `<insert your backup password here>` with your key password.
   
3. Profit  
   Execute the script and see whether your password was correct. If this is the case, all information will be decrypted and displayed.
