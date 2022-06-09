int transmit_init(char *str);
char pem_str[4096];
Action()
{
	int rc;

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
    rc = transmit_init(pem_str);
	lr_message("return codefrom transmit_init = %d", rc);
	lr_message("pem_str from transmit_init = %s", pem_str);

	return 0;
	
}


