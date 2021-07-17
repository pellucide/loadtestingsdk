const http = require('http');
const forge = require('node-forge')
const supportedRoutes = {"supportedRoutes":
                            [  {"method": "POST",
                                 "route": "/contentSignature",
                                 "bodyJson": "{\"content\":\"content ASCII\",\"contentB64\":\"Base64 encoded content\",\"privateKey\":\"private key in PEM format\"}",
                                 "responseJson": "{\"signatureB64\":\"Base64 encoded content signature\"}"
                               }
                            ]
                        };

const requestListener = function (req, res) {
    res.setHeader("Content-Type", "application/json");
    switch (req.url) {
        case "/contentSignature": 
             if (req.method == "GET") {
                 sendError(res);
                 break;
             } else if (req.method == "POST") {
                 var body = "";
                 req.on("data", function(chunk) {
                     body += chunk;
                 })

                 req.on("end", function() {
                     // process body
                     let jsonData = JSON.parse(body)
                     console.log(jsonData)
                     if (!jsonData || !(jsonData.contentB64 || jsonData.content) || !jsonData.privateKey) {
                         sendError(res);
                     } else {
                         res.writeHead(200)
                         //parse private key
                         //let privatekeyNoHeader = jsonData.privateKey
                         //.replace(/[\n\r]*-----BEGIN.*[\r\n]+/m, '')
                         //.replace(/[\n\r]+-----END.*[\n\r]+/m, '');
                         //console.log(privatekeyNoHeader);

                         let privatekey1 = jsonData.privateKey.replace(/[\n\r]*/m, '');
                         let privateKey = forge.pki.privateKeyFromPem(privatekey1);

                         //create signature
                         let md = forge.md.sha256.create();
                         let contentData =  jsonData.content
                         if (!jsonData.content) {
                             contentData = forge.util.decode64(jsonData.contentB64);
                         }
                         md.update(contentData, "utf8");
                         let signature = privateKey.sign(md);
                         let signatureB64 = forge.util.encode64(signature);
                         let responseData = { "signatureB64": signatureB64 }
                         res.end(JSON.stringify(responseData));
                     }
                 })
             } else {
                 sendError(res);
             }
             break;
        default :
             sendError(res);
             break;
    }
}

function sendError(res) { 
    res.writeHead(404);
    res.end(JSON.stringify(supportedRoutes));
}

const server = http.createServer(requestListener);

server.listen(8080);

