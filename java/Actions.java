import org.json.JSONArray;
import org.json.JSONObject;

import java.security.*;
import java.util.Iterator;

public class Actions {
    public int init() throws Throwable {
            /*
            try {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
                SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
                keyGen.initialize(1024, random);
                KeyPair pair = keyGen.generateKeyPair();
                PrivateKey priv = pair.getPrivate();
                PublicKey pub = pair.getPublic();
                System.out.println("pub="+pub);
                 */


                /*
                String url = "https://google.com";
                String filePath = "Google.html";

                URL urlObj = new URL(url);
                URLConnection urlCon = urlObj.openConnection();

                InputStream inputStream = urlCon.getInputStream();
                BufferedInputStream reader = new BufferedInputStream(inputStream);

                BufferedOutputStream writer = new BufferedOutputStream(new FileOutputStream(filePath));

                byte[] buffer = new byte[4096];
                int bytesRead = -1;

                while ((bytesRead = reader.read(buffer)) != -1) {
                    writer.write(buffer, 0, bytesRead);
                }

                writer.close();
                reader.close();
                System.out.println("buffer[0]="+buffer[0]);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (NoSuchProviderException e) {
                e.printStackTrace();
            }
        */
        Transmit transmit = new Transmit();
        String userId = "jagat";
        String sessionName = transmit.getRandomString(11);
        transmit.setCurrentSession(sessionName, userId);
        transmit.generateTimeStamp();
        transmit.generateRsaKeyPair();
        transmit.generateEcKeyPair();
        String response = transmit.bind();
        transmit.processResponse(response);
        // bind done //
        ///////////////



        ///////////////////
        // form session ///
        int scheme = 4;
        String appId = transmit.getAppId();
        String appData = transmit.getSessionVar("appData");
        String assertionId = transmit.getSessionVar("assertionId");
        String challenge = transmit.getSessionVar("challenge");
        String deviceId = transmit.getSessionVar("deviceId");
        String sessionId = transmit.getSessionVar("sessionId");
        String path="/api/v2/auth/assert?aid="+appId+"&did="+deviceId+"&sid="+sessionId;
        String body = "{\"headers\":[{\"type\":\"uid\",\"uid\":\""+userId+"\"}],\"data\":{\"action\":\"form\",\"assert\":\"action\",\"assertion_id\":\""+assertionId+
                "\",\"fch\":\""+challenge+"\",\"input\":"+appData+"}}";

        transmit.preProcess(path, body, scheme);
        response = transmit.sendPost(path, body);
        transmit.processResponse(response);
        // form session done ///
        ////////////////////////

        ////////////////////////
        // Password session ///
        String passwordValue = "1234";
        assertionId = transmit.getSessionVar("assertionId");
        challenge = transmit.getSessionVar("challenge");
        deviceId = transmit.getSessionVar("deviceId");
        sessionId = transmit.getSessionVar("sessionId");
        path="/api/v2/auth/assert?aid="+appId+"&did="+deviceId+"&sid="+sessionId;
        body = transmit.processPasswordAuthentication(passwordValue, challenge, assertionId);
        transmit.preProcess(path, body, scheme);

        response = transmit.sendPost(path, body);
        transmit.processResponse(response);
        // Password session done ///
        ////////////////////////////


        ///////////////////////////
        // Confirmation session ///
        JSONObject controlFlow = transmit.getControlFlow();
        String continue_button_text = controlFlow.getString("continue_button_text");
        String cancel_button_text = controlFlow.getString("cancel_button_text");
        String control_flow_text = controlFlow.getString("text");
        String control_flow_title = controlFlow.getString("title");
        String control_flow_type = controlFlow.getString("type");
        assertionId = transmit.getSessionVar("assertionId");
        challenge = transmit.getSessionVar("challenge");
        deviceId = transmit.getSessionVar("deviceId");
        sessionId = transmit.getSessionVar("sessionId");

        String payloadToSign = "{\"params\":{\"title\":\""+control_flow_title+"\",\"text\":\""+control_flow_text+"\",\"continue_button_text\":\""+continue_button_text+"\",\"cancel_button_text\":\""+cancel_button_text+"\",\"parameters\":[]},\"user_input\":\""+continue_button_text+"\"}";
        String payloadSignature = transmit.signRsa(payloadToSign);

        String from = "\"";
        String to = "\\\\\\\"";
        String payload = payloadToSign.replaceAll(from, to);
        path="/api/v2/auth/assert?aid="+appId+"&did="+deviceId+"&sid="+sessionId;
        body = "{\"headers\":[{\"type\":\"uid\",\"uid\":\""+userId+"\"}],\"data\":{\"action\":\"confirmation\",\"assert\":\"action\",\"assertion_id\":\""+assertionId+"\",\"fch\":\""+challenge+"\",\"data\":{\"user_cancelled\":false,\"sign_content_data\":{\"payload\":\""+payload+"\",\"signed_payload\":\""+payloadSignature+"\"}}}}";
        System.out.println(body);
        transmit.preProcess(path, body, scheme);

        response = transmit.sendPost(path, body);
        transmit.processResponse(response);
        // Confirmation session done ///
        ////////////////////////////////


        ///////////////////////
        // Pin Registration ///
        assertionId = transmit.getSessionVar("assertionId");
        challenge = transmit.getSessionVar("challenge");
        deviceId = transmit.getSessionVar("deviceId");
        sessionId = transmit.getSessionVar("sessionId");

        body = "---undefined1---";
        controlFlow = transmit.getControlFlow();
        if (controlFlow.get("type").equals("registration")) {
            JSONObject assertion0 = controlFlow.getJSONArray("assertions").getJSONObject(0);
            if (assertion0.get("method").equals("pin")) {
                String pinAssertionId = assertion0.getString("assertion_id");
                body = transmit.processPinRegistration(challenge, pinAssertionId);
            }
        }
        if (controlFlow.get("type").equals("authentication")) {
            JSONArray methods = controlFlow.getJSONArray("methods");
            for (Object o : methods) {
                JSONObject method = (JSONObject) o;
                assertionId = method.getString("assertion_id");
                String type = method.getString("type");
                if (type.equals("pin")) {
                    body = transmit.processPinAuthentication(challenge, assertionId);
                }
            }
        }
        path="/api/v2/auth/assert?aid="+appId+"&did="+deviceId+"&sid="+sessionId;
        transmit.preProcess(path, body, scheme);

        response = transmit.sendPost(path, body);
        transmit.processResponse(response);
        // Pin Registration done ///
        ////////////////////////////


        /////////////////////////
        // Pin Authentication ///
        assertionId = transmit.getSessionVar("assertionId");
        challenge = transmit.getSessionVar("challenge");
        deviceId = transmit.getSessionVar("deviceId");
        sessionId = transmit.getSessionVar("sessionId");

        body = "---undefined1---";
        controlFlow = transmit.getControlFlow();
        if (controlFlow.get("type").equals("registration")) {
            JSONObject assertion0 = controlFlow.getJSONArray("assertions").getJSONObject(0);
            if (assertion0.get("method").equals("pin")) {
                String pinAssertionId = assertion0.getString("assertion_id");
                body = transmit.processPinRegistration(challenge, pinAssertionId);
            }
        }
        if (controlFlow.get("type").equals("authentication")) {
            JSONArray methods = controlFlow.getJSONArray("methods");
            for (Object o : methods) {
                JSONObject method = (JSONObject) o;
                assertionId = method.getString("assertion_id");
                String type = method.getString("type");
                if (type.equals("pin")) {
                    body = transmit.processPinAuthentication(challenge, assertionId);
                }
            }
        }
        path="/api/v2/auth/assert?aid="+appId+"&did="+deviceId+"&sid="+sessionId;
        transmit.preProcess(path, body, scheme);

        response = transmit.sendPost(path, body);
        transmit.processResponse(response);
        // Pin Authentication done ///
        //////////////////////////////



        // Logout  ///
        //////////////
        deviceId = transmit.getSessionVar("deviceId");
        sessionId = transmit.getSessionVar("sessionId");

        body = "{\"headers\":[{\"type\":\"uid\",\"uid\":\""+userId+"\"}],\"data\":{}}";
        path="/api/v2/auth/logout?aid="+appId+"&did="+deviceId+"&sid="+sessionId;
        transmit.preProcess(path, body, scheme);

        response = transmit.sendPost(path, body);
        transmit.processResponse(response);
        // Logout done ///
        //////////////////


        ///////////////////////
        //// Login request ////
        transmit.generateTimeStamp();
        deviceId = transmit.getSessionVar("deviceId");
        body="{\"headers\":[{\"type\":\"uid\",\"uid\":\""+userId+"\"}],\"data\":{\"collection_result\":{\"metadata\":{\"scheme_version\":2,\"version\":\"6.1.06531\",\"timestamp\":"+"1626537490"+"},\"content\":{\"hw_authenticators\":{\"fido\":[{\"aaid\":\"1206#0001\"},{\"aaid\":\"1206#0002\"},{\"aaid\":\"1206#0003\"}],\"device_biometrics\":{\"supported\":false,\"user_registered\":false},\"fingerprint\":{\"supported\":true,\"user_registered\":true},\"face_id\":{\"supported\":false,\"user_registered\":false}},\"device_details\":{\"logged_users\":1,\"persistence_mode\":\"false\",\"hw_type\":\"Phone\",\"tampered\":true,\"sim_operator\":\"310260\",\"roaming\":false,\"master_key_generated\":1625247266100,\"device_model\":\"GoogleAOSP\",\"last_reboot\":261332,\"tz\":\"AmericaNew_York\",\"os_version\":\"9\",\"jailbroken\":false,\"security_patch\":\"20190805\",\"sim_operator_name\":\"TMobile\",\"frontal_camera\":true,\"device_name\":\"a42fb947dc6e7621\",\"known_networks\":[{\"ssid\":\"03639c4e63344bebfb9ca2ef1df05646\"}],\"has_hw_security\":false,\"screen_lock\":true,\"os_type\":\"Android\",\"sflags\":2147483647,\"supported_abis\":[\"x86\",\"armeabiv7a\",\"armeabi\"],\"boot_loader\":\"unknown\",\"base_os\":\"\"},\"installed_packages\":[\"c048a5dd4096addf0634f3e9d3c4cc5c\",\"50cf77a99066ed0902cafa5f293a85a9\",\"5c29ff6c35fce8d75062ad9d4bd24d3e\",\"5ee6428585a420c1fee676a368fcec3c\",\"b7c039c51c133a83a8096a098526d731\",\"072f89bcb516dc438e1abd2849158ef0\",\"d4cb521a8bffdf30c3ed325aa656de81\",\"6c1171ad3c0979c7a84dbbf086922599\",\"a0be66ff10fad8551d154afc065537fc\",\"7ad20db616ba8b277fd77cd3ee0748f7\",\"0489f76fd6ad1327a19ab002cee45a31\"],\"collector_state\":{\"accounts\":\"disabled\",\"devicedetails\":\"active\",\"contacts\":\"disabled\",\"owner\":\"active\",\"software\":\"active\",\"location\":\"active\",\"locationcountry\":\"active\",\"bluetooth\":\"disabled\",\"externalsdkdetails\":\"active\",\"hwauthenticators\":\"active\",\"capabilities\":\"active\",\"fidoauthenticators\":\"active\",\"largedata\":\"active\",\"localenrollments\":\"active\",\"devicefingerprint\":\"active\",\"apppermissions\":\"disabled\"},\"local_enrollments\":{\"pin\":{\"registration_status\":\"registered\",\"validation_status\":\"validated\"}}}},\"push_token\":\"dummy_token\",\"policy_request_id\":\"default_auth\",\"params\":{}}}";
        path="/api/v2/auth/login?aid="+appId+"&did="+deviceId;
        transmit.preProcess(path, body, scheme);

        response = transmit.sendPost(path, body);
        transmit.processResponse(response);
        //// Login request done ////
        ////////////////////////////


        ////////////////////////
        // Password session ///
        passwordValue = "1234";
        assertionId = transmit.getSessionVar("assertionId");
        challenge = transmit.getSessionVar("challenge");
        deviceId = transmit.getSessionVar("deviceId");
        sessionId = transmit.getSessionVar("sessionId");
        path="/api/v2/auth/assert?aid="+appId+"&did="+deviceId+"&sid="+sessionId;
        body = transmit.processPasswordAuthentication(passwordValue, challenge, assertionId);
        transmit.preProcess(path, body, scheme);

        response = transmit.sendPost(path, body);
        transmit.processResponse(response);
        // Password session done ///
        ////////////////////////////



        // Logout  ///
        //////////////
        deviceId = transmit.getSessionVar("deviceId");
        sessionId = transmit.getSessionVar("sessionId");

        body = "{\"headers\":[{\"type\":\"uid\",\"uid\":\""+userId+"\"}],\"data\":{}}";
        path="/api/v2/auth/logout?aid="+appId+"&did="+deviceId+"&sid="+sessionId;
        transmit.preProcess(path, body, scheme);

        response = transmit.sendPost(path, body);
        transmit.processResponse(response);
        // Logout done ///
        //////////////////


        return 0;
    }//end of init

    public int action() throws Throwable {
        return 0;
    }//end of action


    public int end() throws Throwable {
        return 0;
    }//end of end
}
