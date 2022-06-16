int transmit_init(char *str, char* str1);
char pem_str_public[2096];
char pem_str_private[2098];
char requestBody[2999];
char contentSignature[1555];
char test[22] = "Hello World!";
int test_out_len = 64;
char test_out[264];
char test_out2[3266];
char body[3999];
char path[256], urlPath[256];


int transmit_bind(char * userId, char * clientVersion, int scheme, char * appId, char *path, char * body, char * contentSignature, char * debugString);
void base64decode (const void *b64_decode_this, int decode_this_many_bytes, char *decoded, int * outlen);
void base64encode (const void *b64_encode_this, int encode_this_many_bytes, char *outbuf, int *outlen);
void getSha256(char * inbuf, int inlen, char * outbuf, int *outlen);
void byteArrayToHexString(char * byteArray, int inlen, char * hexString);
void transmit_preProcess(char * path, char * body, char * clientVersion, char * deviceId, int scheme, char* contentSignature, char * debugString);

Action()
{
	int rc;
	char * userId = "test";
	char * clientVersion = "6.0.0 (7427);[1,2,3,6,7,8,10,11,12,14,28,19]";
	char * appId= "mobile";
	char * authorization= "TSToken 6d6c4d9a-b57a-4c07-bbcc-07ce59dd97dc; tid=mobileeverything";
	int ii=0;
	char deviceId[64], sessionId[64], challenge[64], assertionId[64];
	char * test_out1;
	char * response;
	int scheme=4;

	/*
	rc = lr_load_dll("C:\\Users\\jagat_brahma\\Documents\\VuGen\\Scripts\\CVuser2\\libsodium-23.dll");
	lr_message("return code = %d", rc);
	rc=sodium_init();
    lr_message("return code = %d", rc);
    */
				
    rc = lr_load_dll("libcrypto-lt-1_1.dll");
    lr_message("return code = %d", rc);
    
    //rc = lr_load_dll("C:\\Users\\jagat_brahma\\Documents\\VuGen\\Scripts\\CVuser2\\libsodium.dll");
	//lr_message("return code = %d", rc);
	
	rc = lr_load_dll("C:\\Users\\jagat_brahma\\Documents\\VuGen\\Scripts\\CVuser2\\libsodium-23.dll");
	lr_message("return code = %d", rc);
	
	//rc = lr_load_dll("C:\\Users\\jagat_brahma\\Documents\\VuGen\\Scripts\\CVuser2\\libcrypto-1_1.dll");
	//lr_message("return code = %d", rc);
	
    rc = lr_load_dll("C:\\Users\\jagat_brahma\\Documents\\VuGen\\Scripts\\CVuser2\\libcrypto-3.dll");
	lr_message("return code = %d", rc);
	
    rc = lr_load_dll("C:\\Users\\jagat_brahma\\Documents\\VuGen\\Scripts\\CVuser2\\libssl-3.dll");
	lr_message("return code = %d", rc);
	
	rc = lr_load_dll("C:\\Users\\jagat_brahma\\Documents\\VuGen\\Scripts\\CVuser2\\transmitlib.dll");
	lr_message("return code = %d", rc);

		
	rc = lr_load_dll("C:\\Users\\jagat_brahma\\Documents\\VuGen\\Scripts\\CVuser2\\msys-cjson-1.dll");
	lr_message("return code = %d", rc);

    rc = transmit_init(pem_str_public, pem_str_private);
	lr_message("return codefrom transmit_init = %d", rc);
	lr_message("pem_str_public from transmit_init = %s--", pem_str_public);
	lr_message("pem_str_private from transmit_init = %s--", pem_str_private);
	
		
	lr_message("test[12] = %s", test);
	base64encode(test, 12, test_out, &test_out_len);
	test_out[test_out_len] = 0;
	lr_message("test_out[%d] = %s", test_out_len, test_out);

	base64decode(test_out, 16, test_out2, &test_out_len);
	lr_message("test_out2[%d] = %s", test_out_len, test_out2);
	
	getSha256(test, 12, test_out, &test_out_len);
	lr_message("test_out_len = %d", test_out_len);	
	
	byteArrayToHexString(test_out, test_out_len, test_out2);
	test_out2[test_out_len*2]=0;
	lr_message("test_out2[%d] = %s", test_out_len*2, test_out2);
	
	
	
	

	rc = transmit_bind(userId, clientVersion, scheme, appId, path, body, contentSignature, test_out2);	
	lr_message("return codefrom transmit_bind = %d", rc);
	lr_message("path from transmit_bind = %s", path);
	lr_message("body from transmit_bind = %s", body);
	lr_message("contentSignature from transmit_bind = %s", contentSignature);

	
	
	
	sprintf(requestBody, "Body=%s", body);
	web_set_sockets_option("SSL_VERSION", "AUTO");
	web_add_auto_header("X-TS-Client-Version", 	"6.0.0 (7427);[1,2,3,6,7,8,10,11,12,14,28,19]");
	web_add_auto_header("loadrunnertest", "true");
    web_add_auto_header("headerforperftest", "false");
    web_add_auto_header("authorization", authorization);
    
    web_reg_save_param("response", "LB=", "RB=", "Search=Body", LAST);
	
	web_custom_request("bind", 
		"URL=https://jagat.tsdemo.transmit-field.com/api/v2/auth/bind?aid=mobile&locale=en-US", 
		"Method=POST", 
		"Resource=0", 
		"RecContentType=application/json", 
		"Referer=", 
		"Snapshot=t3.inf", 
		"Mode=HTML", 
		"EncType=application/json", 
        requestBody, 
		LAST);
    

        
    response = lr_eval_string("{response}");
    lr_message("respose from transmit_bind = %s", response);
    rc = transmit_processResponse(response, deviceId, sessionId, challenge, assertionId);
    lr_message("respose from transmit_processResponse = %d", rc);
    lr_message("deviceId = %s", deviceId);
    lr_message("sessionId = %s", sessionId);
    lr_message("challenge = %s", challenge);
    lr_message("assertionId = %s", assertionId);

    
    sprintf(path, "%s%s%s%s%s%s", "/api/v2/auth/assert?aid=",appId, "&did=", deviceId, "&sid=", sessionId);
    transmit_processPasswordAuthentication(userId, "test", challenge, assertionId, body);
    transmit_preProcess(path, body, clientVersion, deviceId, scheme, contentSignature, test_out2);
	lr_message("path = %s", path);
	lr_message("body from transmit_preProcess = %s", body);
	lr_message("contentSignature from transmit_preProcess = %s", contentSignature);
	lr_message("test_out2 from transmit_preProcess = %s", test_out2);
	sprintf(requestBody, "Body=%s", body);
	sprintf(urlPath, "URL=%s%s","https://jagat.tsdemo.transmit-field.com", path);
	web_add_header("Content-Signature", contentSignature);
	web_reg_save_param("response", "LB=", "RB=", "Search=Body", LAST);
	web_custom_request("assert", 
		 urlPath,
		"Method=POST", 
		"Resource=0", 
		"RecContentType=application/json", 
		"Referer=", 
		"Snapshot=t3.inf", 
		"Mode=HTML", 
		"EncType=application/json", 
        requestBody, 
		LAST);        
    response = lr_eval_string("{response}");
    lr_message("respose from transmit_assert = %s", response);
    return 0; 	

}

	

