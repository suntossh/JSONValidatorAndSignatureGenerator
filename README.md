JSON-Decoder-chrome-ext

## Overview

The JSON Decoder is created to create a signature of Payment request using your Payment Payload consisting of metadata and request and your private key.

## Features

- Parse and validate any JSON.
- Extract PKCS#8 private key from a P12.
- Using PKCS#8 and JSON Payment request generate a digital signature and update in JSON payload.

## Installation

Follow these simple steps to install the JWT Decoder Chrome Extension:

1. Clone the repository:

   ```bash
   git clone https://github.com/suntossh/JSONDecoderChromeExtn.git

2. Open Chrome and navigate to chrome://extensions/.
3. Enable "Developer mode" in the top right.
4. Click on "Load unpacked" and select the directory where you cloned the repository.

## How to Use
1. After installation, locate the extension icon in the top-right corner of your Chrome browser.
2. Click on the extension icon to open the JSON Decoder.
3. Select JSON and parse it.
4. Select p12 and provide password to extract the PKCS#8.
5. Now generate a signature and update JSON.
6. Now JSON is ready to be tested.
