
let globalConstant = 'Hari Bol';


// Example function to update the global constant
function updateGlobalConstant(newValue) {
  globalConstant = newValue;
}

document.getElementById('parseButton').addEventListener('click', () => {
  const input = document.getElementById('jsonInput').value;
  const messageContent = document.getElementById('messageContent').value;
  try {
    const parsed = JSON.parse(input);
    const jsonObject = JSON.parse(input);
    parsed.request.message=messageContent;
    const requestObject = jsonObject.request.textContent;
    updateGlobalConstant(requestObject);
    document.getElementById('output').textContent = JSON.stringify(parsed, null, 2);
  } catch (error) {
    document.getElementById('output').textContent = 'Invalid JSON: ' + error.message;
  }
});


document.getElementById('signButton').addEventListener('click', async () => {
  const fileInput = document.getElementById('p12FileInput');
  const password = document.getElementById('p12PasswordInput').value;

  try {
    const arrayBuffer = await fileInput.files[0].arrayBuffer();
    const privateKey = await extractPrivateKey(arrayBuffer, password);

    if (privateKey) {
      //alert("globalConstant"+globalConstant);
      //const requestString = JSON.stringify(globalConstant);
      const input = document.getElementById('output').textContent;  
      const jsonObject = JSON.parse(input);
      const requestString = JSON.stringify(jsonObject.request);
      //alert("requestString="+requestString);  
      const signature = signRequest(requestString, privateKey);
//todo
      document.getElementById('signatureOutput').textContent = "Signature:\n" + signature;
      //const parsed = JSON.parse(input);
      jsonObject.metadata.signature=signature;
      document.getElementById('output').textContent = JSON.stringify(jsonObject, null, 2);
      document.getElementById('signaturedMessage').textContent = JSON.stringify(jsonObject, null, 2);
    } else {
      throw new Error('Failed to extract private key.');
    }
  } catch (error) {
    document.getElementById('signatureOutput').textContent = 'Error: ' + error.message;
  }
});

async function extractPrivateKey(p12ArrayBuffer, password) {
  try {
    const p12Der = forge.util.createBuffer(p12ArrayBuffer);
    const p12Asn1 = forge.asn1.fromDer(p12Der);
    const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password);

    const bags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
    const keyBag = bags[forge.pki.oids.pkcs8ShroudedKeyBag][0];
    const privateKey = keyBag.key;

    return privateKey;
  } catch (error) {
    throw new Error('Failed to extract private key: ' + error.message);
  }
}

function signRequest(data, privateKey) {
  //alert(data);
  const md = forge.md.sha256.create();
  md.update(data, 'utf8');
  const signature = privateKey.sign(md);
  return forge.util.encode64(signature);
}

function formatPrivateKey(privateKey) {
  // Split by lines
  const lines = privateKey.trim().split('\n');
  // Remove first and last lines
  const trimmedLines = lines.slice(1, -1);
  // Join remaining lines into a single string
  const formattedPrivateKey = trimmedLines.join('');
  return formattedPrivateKey;
}

document.getElementById('extractButton').addEventListener('click', () => {
  const fileInput = document.getElementById('p12FileInput');
  const passwordInput = document.getElementById('p12PasswordInput');
  //const outputElement = document.getElementById('p12Output');
  const outputElementForSignature = document.getElementById('p13Output');

  if (fileInput.files.length === 0) {
      //outputElement.textContent = 'Please select a P12 file.';
      outputElementForSignature.textContent = 'Please select a P12 file.';
      return;
  }

  const file = fileInput.files[0];
  const password = passwordInput.value;

  const reader = new FileReader();
  reader.onload = (event) => {
      const arrayBuffer = event.target.result;
      try {
          const privateKeyPem = extractPrivateKeyFromP12(arrayBuffer, password);
          //outputElement.textContent = privateKeyPem;
          outputElementForSignature.textContent = "PKCS#8:\n" + formatPrivateKey(privateKeyPem)

      } catch (err) {
          outputElement.textContent = `Error extracting private key: ${err.message}`;
      }
  };
  reader.readAsArrayBuffer(file);
});

function extractPrivateKeyFromP12(arrayBuffer, password) {
  const p12Der = new Uint8Array(arrayBuffer);
  const p12Asn1 = forge.asn1.fromDer(forge.util.binary.raw.encode(p12Der));
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password);

  let privateKeyPem = '';
  p12.safeContents.forEach(safeContents => {
      safeContents.safeBags.forEach(safeBag => {
          if (safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag || safeBag.type === forge.pki.oids.keyBag) {
              const privateKey = safeBag.key;
              const privateKeyInfo = forge.pki.privateKeyToAsn1(privateKey);
              const pkcs8 = forge.asn1.create(
                  forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
                      forge.asn1.create(
                          forge.asn1.Class.UNIVERSAL, forge.asn1.Type.INTEGER, false,
                          forge.util.hexToBytes('00')),
                      forge.asn1.create(
                          forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
                              forge.asn1.create(
                                  forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false,
                                  forge.asn1.oidToDer(forge.pki.oids.rsaEncryption).getBytes()),
                              forge.asn1.create(
                                  forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, '')
                          ]),
                      forge.asn1.create(
                          forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false,
                          forge.asn1.toDer(privateKeyInfo).getBytes())
                  ]);
              privateKeyPem = forge.pki.privateKeyInfoToPem(pkcs8);
          }
      });
  });

  if (privateKeyPem === '') {
      throw new Error('No private key found in the provided P12 file.');
  }

  return privateKeyPem;
}

function copyToClipboard() {
  // Get the text from the jsonOutput element
  const jsonOutput = document.getElementById('signaturedMessage').textContent;
  
  // Use the Clipboard API to copy the text
  navigator.clipboard.writeText(jsonOutput).then(function() {
      alert('JSON copied to clipboard!');
  }).catch(function(err) {
      alert('Failed to copy text: ', err);
  });
}