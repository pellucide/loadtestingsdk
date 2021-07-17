const force = require('node-forge')
const http = require('http')
var public_key_noheader
var rsa = force.pki.rsa;
var pki = force.pki;

// generate an RSA key pair 
var keypair = rsa.generateKeyPair({bits: 512, e: 0x10001});
var private_key_pem = force.pki.privateKeyToPem(keypair.privateKey);
var public_key_pem = force.pki.publicKeyToPem(keypair.publicKey,500);
//console.log(private_key_pem)
//console.log(public_key_pem)

//var publickeyNoHeader = public_key_pem.replace(/[\n\r]*-----BEGIN.*[\r\n]+/m, '').replace(/[\n\r]+-----END.*[\n\r]+/m, "");
//var privatekeyNoHeader = private_key_pem.replace(/[\n\r]*-----BEGIN.*[\r\n]+/m, '').replace(/[\n\r]+-----END.*[\n\r]+/m, '');
//console.log(privatekeyNoHeader)
//console.log(publickeyNoHeader)

var privateKey = pki.privateKeyFromPem(private_key_pem)
var publicKey = pki.publicKeyFromPem(public_key_pem)

let content = "test content"
let contentB64 = force.util.encode64(content);
let body = {"contentB64":contentB64, "privateKey":private_key_pem};
//let body = {"content":content, "privateKey":private_key_pem};
let bodyStr= JSON.stringify(body)

//ShA265 hash
var md = force.md.sha256.create();
md.update(content, "utf8");
var signatureData = privateKey.sign(md);
var signatureB64 = force.util.encode64(signatureData);

//console.log(connectionSettings.url);
//console.log(body)

const httpOptions = {
       hostname: "localhost",
       port:8080,
       path:`/contentSignature`,
       method:'POST',
       headers: {  
           'Content-Type': 'application/json',
           'Content-Length': bodyStr.length
       }
}

const req = http.request(httpOptions, resp => {
  let data = '';

  // A chunk of data has been received.
  resp.on('data', (chunk) => {
    data += chunk;
  });

  // The whole response has been received.
  resp.on('end', () => {
      let jsonData = JSON.parse(data)
      console.log(JSON.stringify(jsonData, null, 3))
      let signatureB64 = jsonData.signatureB64;
      let signatudeData = force.util.decode64(jsonData.signatureB64);
      let digest = force.md.sha256.create();
      digest.update(content, "utf8");
      let localSignature = privateKey.sign(digest);
      let localSignatureB64 = force.util.encode64(localSignature)
      console.log("locally generated signature =   " +localSignatureB64);
      console.log("serverly generated signature =  " +jsonData.signatureB64);

      // not working
      //let result = publicKey.verify(digest, signatureData);
      //console.log(result);

  });

}).on("error", (err) => {
  console.log("Error: " + err.message);
});

req.write(bodyStr)
req.end()

