
import java.io.*;
import java.lang.StringBuilder;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Date;
import java.util.Base64;
import java.util.*;
import org.json.*;

class Transmit {
    HashMap<String, String> predefinedVars = new HashMap<>();
    HashMap<String, String> headers = new HashMap<>();

    HashMap<String, String> vars = new HashMap<>();
    Signature rsaSign;
    Signature ecSign;
    KeyFactory ecFactory;
    KeyFactory rsaFactory;
    KeyPairGenerator grsa;
    PublicKey ecPublicKey;
    PrivateKey ecPrivateKey;
    PublicKey rsaPublicKey;
    PrivateKey rsaPrivateKey;
    ECGenParameterSpec ecSpec;
    KeyPairGenerator gec;
    MessageDigest digest;

    Transmit() {
        try {
            rsaSign = Signature.getInstance("SHA256withRSA");
            ecSign = Signature.getInstance("SHA256withECDSA");
            ecFactory = KeyFactory.getInstance("EC");
            rsaFactory = KeyFactory.getInstance("RSA");
            grsa = KeyPairGenerator.getInstance("RSA");
            ecSpec = new ECGenParameterSpec("secp256k1");
            gec = KeyPairGenerator.getInstance("EC");
            gec.initialize(ecSpec, new SecureRandom());
            grsa.initialize(1024);
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
        predefinedVars.put("url", "jagat.tsdemo.transmit-field.com");
        predefinedVars.put("appid", "mobile");
        predefinedVars.put("tokenId", "mobileeverything");
        predefinedVars.put("tokenValue", "6d6c4d9a-b57a-4c07-bbcc-07ce59dd97dc");
        //predefinedVars.put("X-TS-Client-Version-4.1", "4.1 (6540);[1,2,3,6,7,8,10,11,12,14,19]");
        predefinedVars.put("X-TS-Client-Version-6.1.0", "6.1.0 (7464);[1,2,3,6,7,8,10,11,12,14,28,19]");


        headers.put("Content-Type", "application/json");
        headers.put("x-ts-client-version", predefinedVars.get("X-TS-Client-Version-6.1.0"));
        headers.put("authorization", "TSToken " + predefinedVars.get("tokenValue") + "; tid=" + predefinedVars.get("tokenId"));
        headers.put("jmetertest", "true");
        headers.put("headerforperftest", "false");
    }


    public void setCurrentSession(String sessionName) {
        vars.put("currentSesion", sessionName);
    }

    public void setCurrentSession(int sessionName) {
        setCurrentSession("" + sessionName);
    }

    public String getCurrentSession() {
        return vars.get("currentSesion");
    }


    public String getUserName() {
        String sessionName = getCurrentSession();
        return vars.get(sessionName);
    }

    public void putUserName(String userName) {
        String sessionName = getCurrentSession();
        vars.put(sessionName, userName);
    }

    public void setCurrentSession(int sessionName, String userName) {
        setCurrentSession(sessionName);
        putUserName(userName);
    }

    public void setCurrentSession(String sessionName, String userName) {
        setCurrentSession(sessionName);
        putUserName(userName);
    }

    public String getSessionVar(String keyName) {
        String sessionName = getCurrentSession();
        String varKeyName = sessionName + keyName;
        return vars.get(varKeyName);
    }

    public void putSessionVar(String keyName, String value) {
        String sessionName = getCurrentSession();
        String varKeyName = sessionName + keyName;
        vars.put(varKeyName, value);
    }


    public String getEcPublicKey() {
        return getSessionVar("ecPublicKeyEncoded");
    }

    public String getEcPrivateKey() {
        return getSessionVar("ecPrivateKeyEncoded");
    }

    public String getRsaPublicKey() {
        return getSessionVar("rsaPublicKeyEncoded");
    }

    public String getRsaPrivateKey() {
        return getSessionVar("rsaPrivateKeyEncoded");
    }

    public JSONObject getControlFlow() {
        String jsonString = getSessionVar("controlFlow");
        //System.out.println("responseData="+jsonString);
        //JSONObject jsonObj = (JSONObject) jsonParser.parse(jsonString);
        return new JSONObject(jsonString);
    }


    public void generateRsaKeyPair() {
        //System.out.println("generateRsaKeyPair()");
        KeyPair keypair = grsa.generateKeyPair();
        PublicKey publicKey = keypair.getPublic();
        PrivateKey privateKey = keypair.getPrivate();
        String publicKeyEncoded = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        String privateKeyEncoded = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        //System.out.println("rsaPublicKeyEncoded" + " = " + publicKeyEncoded);
        //System.out.println("rsaPrivateKeyEncoded" + " = " + privateKeyEncoded);
        //System.out.println("======");
        putSessionVar("rsaPublicKeyEncoded", publicKeyEncoded);
        putSessionVar("rsaPrivateKeyEncoded", privateKeyEncoded);
    }

    public void generateTimeStamp() {
        String timestamp = "" + new Date().getTime();
        //System.out.println("timestamp="+timestamp);
        vars.put("timestamp", timestamp);
    }

    public void generateEcKeyPair() {
        KeyPair keypair = gec.generateKeyPair();
        PublicKey publicKey = keypair.getPublic();
        PrivateKey privateKey = keypair.getPrivate();

        String publicKeyEncoded = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        String privateKeyEncoded = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        //System.out.println("ecPublicKeyEncoded =" + publicKeyEncoded);
        //System.out.println("ecPrivateKeyEncoded =" + " = " + privateKeyEncoded);
        //System.out.println("======");

        putSessionVar("ecPublicKeyEncoded", publicKeyEncoded);
        putSessionVar("ecPrivateKeyEncoded", privateKeyEncoded);
    }



    public String getClientVersion() {
        return predefinedVars.get("X-TS-Client-Version-6.1.0");
    }

    public void processResponse(String jsonString) {
        JSONObject jsonObj = new JSONObject(jsonString);

        int errorCode = jsonObj.getInt("error_code");
        putSessionVar("errorCode", String.valueOf(errorCode));
        System.out.println("errorCode="+ errorCode);

        String errorMessage = jsonObj.getString("error_message");
        putSessionVar("errorMessage", errorMessage);
        System.out.println("errorMessage="+ errorMessage);

        JSONObject jsonObjData = null;
        if (jsonObj.has("data")) {
            jsonObjData = jsonObj.getJSONObject("data");
        }
        if (jsonObjData == null)  {
            return;
        }

        String state = jsonObjData.getString("state");
        if (state != null) {
            putSessionVar("state", state);
            //System.out.println("state = " + state);

            if (state.equals("completed")) {
                String token = jsonObjData.getString("token");
                putSessionVar("token", token);
                //System.out.println("token = " + token);
            } else {
                JSONObject data = jsonObj.getJSONObject("data");
                String challenge = null;
                if (data != null && data.has("challenge"))
                    challenge = data.getString("challenge");
                if (challenge != null && !challenge.trim().equals("")) {
                    putSessionVar("challenge", challenge);
                }
                challenge = getSessionVar("challenge");
                System.out.println("challenge="+ challenge);

                JSONArray controlFlow = null;
                if(data != null && data.has("control_flow")){
                    controlFlow = data.getJSONArray("control_flow");
                }
                putSessionVar("controlFlow", controlFlow.get(0).toString());
                String assertionId = controlFlow.getJSONObject(0).getString("assertion_id");
                if (assertionId != null && !assertionId.trim().equals("")) {
                    putSessionVar("assertionId", assertionId);
                }
                System.out.println("assertionId="+assertionId);

                JSONObject controlFlow0 = controlFlow.getJSONObject(0);
                JSONObject appData = null;
                if (controlFlow0.has("app_data"))
                    appData = controlFlow0.getJSONObject("app_data");
                if (appData != null) {
                    putSessionVar("appData", appData.toString());
                } else {
                    putSessionVar("appData", "");
                }
                System.out.println("appData = " + appData);

                JSONArray methods = null;
                if (controlFlow0.has("methods"))
                    methods = controlFlow0.getJSONArray("methods");
                System.out.println("methods="+methods);
                if (methods != null) {
                    putSessionVar("methods", methods.toString());
                    String assertionId1 = methods.getJSONObject(0).getString("assertion_id");
                    if (assertionId1 != null && !assertionId1.trim().equals("")) {
                        putSessionVar("assertionId", assertionId1);
                    }
                } else {
                    putSessionVar("methods", "");
                }
                assertionId = getSessionVar("assertionId");
                System.out.println("assertionId="+assertionId);


                JSONArray headers = jsonObj.getJSONArray("headers");
                processTransmitJsonHeaders(headers);

                System.out.println("deviceId=" + getSessionVar("deviceId"));
                System.out.println("sessionId=" + getSessionVar("sessionId"));
            }
        }
    }

    public void processTransmitJsonHeaders(JSONArray headers) {
        for (int index=0; index<headers.length(); index++) {
            JSONObject header = headers.getJSONObject(index);
            String headerType = header.getString("type");
            //System.out.println("headerType="+headerType);

            if (headerType.equalsIgnoreCase("device_id")) {
                String deviceId = header.getString("device_id");
                putSessionVar("deviceId", deviceId);
            }
            if (headerType.equalsIgnoreCase("session_id")) {
                String sessionId = headers.getJSONObject(index).getString("session_id");
                putSessionVar("sessionId", sessionId);
            }
        }
    }

    public void loadKeysFromEnv() {
        loadEcKeysFromEnv() ;
        loadRsaKeysFromEnv() ;
    }

    public void loadEcKeysFromEnv() {
        String ecPrivateKeyEncoded = getEcPrivateKey();
        byte[] ecPrivatedata = Base64.getDecoder().decode((ecPrivateKeyEncoded.getBytes()));
        PKCS8EncodedKeySpec ecPrivateSpec = new PKCS8EncodedKeySpec(ecPrivatedata);
        try {
            ecPrivateKey = ecFactory.generatePrivate(ecPrivateSpec);
            //String ecPrivateKeyEncoded = Base64.getEncoder().encodeToString(ecPrivateKey.getEncoded());
            //System.out.println("ecPrivateKeyEncoded = "+ecPrivateKeyEncoded);


            String ecPublicKeyEncoded = getEcPublicKey();
            byte[] ecPublicdata = Base64.getDecoder().decode((ecPublicKeyEncoded.getBytes()));
            X509EncodedKeySpec ecPublicSpec = new X509EncodedKeySpec(ecPublicdata);
            ecPublicKey = ecFactory.generatePublic(ecPublicSpec);
            //String ecPubicKeyEncoded = Base64.getEncoder().encodeToString(ecPublicKey.getEncoded());
            //System.out.println("ecPublicKeyEncoded = "+ecPubicKeyEncoded);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public void loadRsaKeysFromEnv() {
        String privateKeyEncoded = getRsaPrivateKey();
        byte[] privatedata = Base64.getDecoder().decode((privateKeyEncoded.getBytes()));
        PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privatedata);
        try {
            rsaPrivateKey = rsaFactory.generatePrivate(privateSpec);
            //String privateKeyEncoded = Base64.getEncoder().encodeToString(rsaPrivateKey.getEncoded());
            //System.out.println("privateKeyEncoded = "+privateKeyEncoded);

            String publicKeyEncoded = getRsaPublicKey();
            byte[] publicdata = Base64.getDecoder().decode((publicKeyEncoded.getBytes()));
            X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicdata);
            rsaPublicKey = rsaFactory.generatePublic(publicSpec);
            //String pubicKeyEncoded = Base64.getEncoder().encodeToString(rsaPublicKey.getEncoded());
            //System.out.println("publicKeyEncoded = "+pubicKeyEncoded);

        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] sha256(byte[] data) {
        return digest.digest(data);
    }

    public String getContentSignatureRsa(String plaintext, int scheme)
            throws UnsupportedEncodingException, SignatureException, InvalidKeyException {
        String publicKeyEncoded = getRsaPublicKey();
        byte[] publicdata = Base64.getDecoder().decode((publicKeyEncoded.getBytes()));
        byte[] keyIdBytes = sha256(publicdata);
        String publicKeyHash = toHexString(keyIdBytes, "%02x", "");

        System.out.println("publicKeyHash="+ publicKeyHash);

        String sig = signRsa(plaintext);
        String contentSignature = "data:" + sig + ";key-id:" + publicKeyHash + ";scheme:"+ scheme;
        if (scheme != 4) {
            String deviceId = getSessionVar("deviceId");
            contentSignature = "data:" + sig + ";key-id:" + deviceId + ";scheme:"+ scheme;
        }
        return contentSignature;
    }

    public String signEc(String plaintext) throws InvalidKeyException, UnsupportedEncodingException, SignatureException {
        loadKeysFromEnv();
        ecSign.initSign(ecPrivateKey);
        ecSign.update(plaintext.getBytes("UTF-8"));
        byte[] signature = rsaSign.sign();
        return toBase64(signature);
    }

    public String signRsa(String plaintext)
            throws UnsupportedEncodingException, SignatureException, InvalidKeyException {
        loadKeysFromEnv();
        return signRsa(plaintext, rsaPrivateKey);
    }

    public String signRsa(String sessionName, String plaintext)
            throws InvalidKeySpecException, UnsupportedEncodingException, SignatureException, InvalidKeyException {
        String privateKeyEncoded = getRsaPrivateKey();
        byte[] privatedata = Base64.getDecoder().decode((privateKeyEncoded.getBytes()));
        PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privatedata);
        rsaPrivateKey = rsaFactory.generatePrivate(privateSpec);
        return signRsa(plaintext, rsaPrivateKey);
    }

    public String signRsa(String plaintext, PrivateKey privateKey)
            throws InvalidKeyException, UnsupportedEncodingException, SignatureException {
        rsaSign.initSign(privateKey);
        rsaSign.update(plaintext.getBytes("UTF-8"));
        byte[] signature = rsaSign.sign();
        return toBase64(signature);
    }

    public String toBase64(byte[] signature) {
        String sig = Base64.getEncoder().encodeToString(signature);
        return sig;
    }

    public String toHexString(byte[] byteArray, String format, String extraAppend) {
        StringBuilder sb = new StringBuilder();
        for (int ii=0; ii<byteArray.length; ii++) {
            String ss = String.format(format,new Object[]{byteArray[ii]});
            sb.append(ss);
            sb.append(extraAppend);
        }
        return sb.toString();
    }

    public void preProcess(String path, String  body, int scheme)
            throws UnsupportedEncodingException, SignatureException, InvalidKeyException {
        vars.put("body", body);
        vars.put("path", path);
        //System.out.println("path="+path);
        //System.out.println("body="+body);
        String clientVersion = predefinedVars.get("X-TS-Client-Version-6.1.0");
        putSessionVar("body",body);
        String plaintext = path + body;
        if (scheme == 2 || scheme == 3 || scheme == 4) {
            plaintext=path+"%%"+clientVersion+"%%" + body;
        }

        //System.out.println("plaintext="+plaintext);
        //System.out.println(toHexString(plaintext.getBytes("UTF-8"), "%d", ", "));

        String contentSignature = getContentSignatureRsa(plaintext, scheme);
        putSessionVar("contentSignature",contentSignature);
        //System.out.println("contentSignature = '"+ contentSignature +"'");
    }

    public String processPinRegistration(String challenge, String assertionId)
            throws UnsupportedEncodingException, SignatureException, InvalidKeyException {
        String userId = getUserName();
        String localAuthenticationChallenge = challenge + assertionId;
        String fch = signRsa(localAuthenticationChallenge);
        String publicKeyEncoded = getRsaPublicKey();
        String body = "{\"headers\":[{\"type\":\"uid\",\"uid\":\""+userId+
                "\"}],\"data\":{\"action\":\"registration\",\"assert\":\"register\",\"assertion_id\":\""+assertionId+
                "\",\"fch\":\""+fch+"\",\"method\":\"pin\",\"public_key\":{\"key\":\""+publicKeyEncoded+
                "\",\"type\":\"rsa\"},\"version\":\"v2\"}}";
        return body;
    }

    public String processPinAuthentication(String challenge, String assertionId)
            throws UnsupportedEncodingException, SignatureException, InvalidKeyException {
        String userId = getUserName();
        String localAuthenticationChallenge = challenge + assertionId;
        String fch = signRsa(localAuthenticationChallenge);

        String publicKeyEncoded = getRsaPublicKey();
        String body = "{\"headers\":[{\"type\":\"uid\",\"uid\":\""+userId+
                "\"}],\"data\":{\"action\":\"authentication\",\"assert\":\"authenticate\",\"assertion_id\":\""+assertionId+
                "\",\"fch\":\""+fch+"\",\"method\":\"pin\",\"data\":{}}}";
        return body;
    }


    public String processPasswordAuthentication(String passwordValue, String challenge, String assertionId) {
        //System.out.println("processPasswordAuthentication(challenge="+challenge+", assertionId=" + assertionId+")");
        String userId = getUserName();
        String body = "{\"headers\":[{\"type\":\"uid\",\"uid\":\""+userId+
                "\"}],\"data\":{\"action\":\"authentication\",\"assert\":\"authenticate\",\"assertion_id\":\""+assertionId+
                "\",\"fch\":\""+challenge+"\",\"data\":{\"password\":\""+passwordValue+
                "\"},\"method\":\"password\"}}";
        return body;
    }



    //Utility functions

    String DATA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";
    String HEXDATA = "ABCDEF1234567890";
    Random RANDOM = new Random();
    public String getRandomString(int len) {
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            sb.append(DATA.charAt(RANDOM.nextInt(DATA.length())));
        }
        return sb.toString();

    }

    public String getRandomHexString(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(HEXDATA.charAt(RANDOM.nextInt(HEXDATA.length())));
        }
        return sb.toString();
    }


    public long getRandomLong() {
        return RANDOM.nextLong();
    }


    public int getRandomInt() {
        return RANDOM.nextInt();
    }

    public String getAppId() {
        return predefinedVars.get("appid");
    }


    public String bind() {
        String userId = getUserName();
        String publicKey = getRsaPublicKey();
        String ecPublicKey = getEcPublicKey();

        String appId = predefinedVars.get("appid");
        String clientVersion = predefinedVars.get("X-TS-Client-Version-6.1.0");
        String timestamp = vars.get("timestamp");
        String path="/api/v2/auth/bind?aid="+appId;
        int scheme = 4;

        String body = "{"+
                "    \"data\": {"+
                "        \"collection_result\": {"+
                "            \"metadata\": {"+
                "                \"scheme_version\": " + scheme + ","+
                "                \"timestamp\": "+ timestamp+ ","+
                "                \"version\": \""+ clientVersion +"\""+
                "            },"+
                "            \"content\": {"+
                "                \"accounts\": ["+
                "                    {"+
                "                        \"name\": \""+getRandomHexString(32)+"\","+
                "                        \"type\": \""+getRandomHexString(32)+"\""+
                "                    },"+
                "                    {"+
                "                        \"name\": \"b8d2a60277443092b75b9a9f71bce945\","+
                "                        \"type\": \"3330d5072c5971394e189640a9f09b77\""+
                "                    }"+
                "                ],"+
                "                \"capabilities\": {"+
                "                    \"audio_acquisition_supported\": true,"+
                "                    \"dyadic_present\": true,"+
                "                    \"face_id_key_bio_protection_supported\": false,"+
                "                    \"fido_client_present\": true,"+
                "                    \"finger_print_supported\": true,"+
                "                    \"host_provided_features\": \"19\","+
                "                    \"image_acquisition_supported\": true,"+
                "                    \"persistent_keys_supported\": true"+
                "                },"+
                "                \"collector_state\": {"+
                "                    \"accounts\": \"active\","+
                "                    \"bluetooth\": \"active\","+
                "                    \"capabilities\": \"active\","+
                "                    \"contacts\": \"active\","+
                "                    \"devicedetails\": \"active\","+
                "                    \"externalsdkdetails\": \"active\","+
                "                    \"fidoauthenticators\": \"disabled\","+
                "                    \"hwauthenticators\": \"active\","+
                "                    \"largedata\": \"disabled\","+
                "                    \"localenrollments\": \"active\","+
                "                    \"location\": \"active\","+
                "                    \"owner\": \"active\","+
                "                    \"software\": \"active\""+
                "                },"+
                "                \"contacts\": {"+
                "                    \"contacts_count\": 765"+
                "                },"+
                "                \"device_details\": {"+
                "                    \"connection\": \"wifi: 10.103.82.192\","+
                "                    \"device_id\": \""+ getRandomLong()+"\","+
                "                    \"device_model\": \""+ getRandomString(8)+"\","+
                "                    \"device_name\": \""+ getRandomHexString(15)+"\","+
                "                    \"frontal_camera\": true,"+
                "                    \"has_hw_security\": true,"+
                "                    \"hw_type\": \"Phone\","+
                "                    \"jailbroken\": false,"+
                "                    \"known_networks\": ["+
                "                        {"+
                "                            \"ssid\": \"ab2e79dbba72c3866298b74f1a1c6fa6\""+
                "                        },"+
                "                        {"+
                "                            \"secure\": true,"+
                "                            \"ssid\": \"4eb341e247478a5a5ec2ba7d755cc614\""+
                "                        }"+
                "                    ],"+
                "                    \"logged_users\": 0,"+
                "                    \"master_key_generated\": "+getRandomLong() +","+
                "                    \"os_type\": \"Android\","+
                "                    \"os_version\": \"8.0.0\","+
                "                    \"roaming\": false,"+
                "                    \"screen_lock\": true,"+
                "                    \"sflags\": -1,"+
                "                    \"sim_operator\": \"310410\","+
                "                    \"sim_operator_name\": \"\","+
                "                    \"sim_serial\": \""+getRandomLong()+"\","+
                "                    \"subscriber_id\": \"310410035590766\","+
                "                    \"tampered\": true,"+
                "                    \"tz\": \"America/New_York\","+
                "                    \"wifi_network\": {"+
                "                        \"bssid\": \"d4705a482b5be4955808176e48f7371e\","+
                "                        \"secure\": true,"+
                "                        \"ssid\": \"4eb341e247478a5a5ec2ba7d755cc614\""+
                "                    }"+
                "                },"+
                "                \"hw_authenticators\": {"+
                "                    \"face_id\": {"+
                "                        \"secure\": false,"+
                "                        \"supported\": false,"+
                "                        \"user_registered\": false"+
                "                    },"+
                "                    \"fingerprint\": {"+
                "                        \"secure\": true,"+
                "                        \"supported\": true,"+
                "                        \"user_registered\": true"+
                "                    }"+
                "                },"+
                "                \"installed_packages\": ["+
                "                    \"20c496910ff8da1214ae52d3750684cd\","+
                "                    \"09e5b19fffdd4c9da52742ce536e1d8b\","+
                "                    \"5f5ca4b53bed9c75720d7ae1a8b949fc\","+
                "                    \"2ce4266d32140417eebea06fd2d5d9cd\","+
                "                    \"40197bd6e7b2b8d5880b666b7a024ab6\""+
                "                ],"+
                "                \"local_enrollments\": {},"+
                "                \"location\": {"+
                "                    \"enabled\": true,"+
                "                    \"h_acc\": 12.800999641418457,"+
                "                    \"lat\": 40.3528937,"+
                "                    \"lng\": -74.4993894"+
                "                },"+
                "                \"owner_details\": {"+
                "                    \"possible_emails\": ["+
                "                        \"f91c98012706e141b2e3bcc286af5e06\""+
                "                    ],"+
                "                    \"possible_names\": ["+
                "                        \"c3fa673b98c1a9ee6ecc3e38d0381966\""+
                "                    ]"+
                "                }"+
                "            }"+
                "        },"+
                "        \"public_key\": {"+
                "            \"key\": \""+ publicKey +"\","+
                "            \"type\": \"rsa\""+
                "        },"+
                "        \"encryption_public_key\": {"+
                "            \"key\": \""+ publicKey + "\","+
                "            \"type\": \"rsa\""+
                "        }"+
                "    },"+
                "    \"headers\": ["+
                "        {"+
                "            \"type\": \"uid\","+
                "            \"uid\": \""+ userId + "\""+
                "        }"+
                "    ],"+
                "    \"push_token\": \"fakePushToken\""+
                "}";
        vars.put("body", body);
        vars.put("path", path);
        String response;
        try {
            preProcess(path, body, scheme);
            response = sendPost(path,  body);
        } catch (UnsupportedEncodingException | SignatureException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        return response;
    }

    public String sendPost(String path,  String body) {
        String url = "https://"+ predefinedVars.get("url") + path;
        int totalBytes=0;
        byte[] buffer = new byte[4096];
        try {
            URL urlObj = new URL(url);
            HttpURLConnection urlCon = (HttpURLConnection) urlObj.openConnection();
            urlCon.setRequestMethod("POST");
            urlCon.setDoOutput(true);
            Set<Map.Entry<String, String>> hdrs = headers.entrySet();
            for (Map.Entry<String, String> header: hdrs) {
                urlCon.setRequestProperty(header.getKey(), header.getValue());
            }
            String contentSignature = getSessionVar("contentSignature");
            //System.out.println("contentSignature = '"+ contentSignature +"'");
            if (contentSignature != null)
                urlCon.setRequestProperty("Content-Signature", contentSignature);
            /*
            StringBuilder urlParameters = new StringBuilder();
            Set<Map.Entry<String, String>> params = parameters.entrySet();
            for (Map.Entry<String,String> param : params) {
                if (urlParameters.length() != 0) urlParameters.append('&');
                urlParameters.append(URLEncoder.encode(param.getKey(), "UTF-8"));
                urlParameters.append('=');
                urlParameters.append(URLEncoder.encode(String.valueOf(param.getValue()), "UTF-8"));
            }
            byte[] postDataBytes = urlParameters.toString().getBytes(StandardCharsets.UTF_8);
             */
            try(OutputStream os = urlCon.getOutputStream()) {
                byte[] bb = body.getBytes("utf-8");
                os.write(bb, 0, bb.length);
            }
            InputStream inputStream = urlCon.getInputStream();
            BufferedInputStream reader = new BufferedInputStream(inputStream);
            int bytesRead;
            do {
                bytesRead = reader.read(buffer);
                if (bytesRead != -1)
                    totalBytes += bytesRead;
            } while (bytesRead != -1) ;
            reader.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        String response =  new String(buffer, 0, totalBytes);
        System.out.println("response = "+ response);
        return response;
    }
    



    byte[] readBuffer = new byte[194496];
    public String sendGet(String path,  String body) {
        String url = "https://"+ predefinedVars.get("url") + path;
        int totalBytes=0;
        StringBuilder response = new StringBuilder();

        try {
            URL urlObj = new URL(url);
            HttpURLConnection urlCon = (HttpURLConnection) urlObj.openConnection();
            urlCon.setRequestMethod("GET");
            //urlCon.setDoOutput(true);
            Set<Map.Entry<String, String>> hdrs = headers.entrySet();
            for (Map.Entry<String, String> header: hdrs) {
                urlCon.setRequestProperty(header.getKey(), header.getValue());
            }
            String contentSignature = getSessionVar("contentSignature");
            //System.out.println("contentSignature = '"+ contentSignature +"'");
            if (contentSignature != null)
                urlCon.setRequestProperty("Content-Signature", contentSignature);
            /*
            StringBuilder urlParameters = new StringBuilder();
            Set<Map.Entry<String, String>> params = parameters.entrySet();
            for (Map.Entry<String,String> param : params) {
                if (urlParameters.length() != 0) urlParameters.append('&');
                urlParameters.append(URLEncoder.encode(param.getKey(), "UTF-8"));
                urlParameters.append('=');
                urlParameters.append(URLEncoder.encode(String.valueOf(param.getValue()), "UTF-8"));
            }
            byte[] postDataBytes = urlParameters.toString().getBytes(StandardCharsets.UTF_8);
             */

            /*
            try(OutputStream os = urlCon.getOutputStream()) {
                byte[] bb = body.getBytes("utf-8");
                os.write(bb, 0, bb.length);
            }
            */
            InputStream inputStream = urlCon.getInputStream();
            BufferedInputStream reader = new BufferedInputStream(inputStream);
            int bytesRead;
            do {
                bytesRead = reader.read(readBuffer);
                if (bytesRead != -1) {
                    response.append(new String(readBuffer, 0, bytesRead));
                    totalBytes += bytesRead;
                }
            } while (bytesRead != -1) ;
            reader.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        //String response =  new String(readBuffer, 0, totalBytes);
        return response.toString();
    }

    public void deleteDevices(String userId, String appId) {

        System.out.println("========================================================");
        String response = sendGet("/api/v2/mng/devices?uid="+userId+"&aid="+ appId, "");
        JSONObject devicesJson = new JSONObject(response);
        System.out.println("devicesJson = " + response.substring(0,400) );
        JSONArray devices = devicesJson.getJSONArray("data");
        int totalDevices = devices.length();
        for (int index=0; index < totalDevices; index++) {
            JSONObject device = devices.getJSONObject(index);
            String deviceHwId = device.getString("device_hw_id");
            String deleteResponse = sendPost("/api/v2/mng/support/reset/device/physical?uid=" + userId + "&deviceHwId=" + deviceHwId, "");
            System.out.println("deleteResponse = " + deleteResponse );
        }
    }

}
