//--------------------------------------------------------------------
// Include Files
#include "lrun.h"
#include "web_api.h"
#include "lrw_custom_body.h"
Action()
{


	
	web_set_sockets_option("SSL_VERSION", "AUTO");

    char * response = web_reg_save_param("c_PasswordMessageServlet","LB=","RB=",
 //"notfound=warning",
 "Search=Body",
 LAST);
	
	lr_eval_string("c_PasswordMessageServlet");
	web_custom_request("get-version-required-v1",
		"URL=https://mcg-api-tst2.unionbank.com/m-api/http/pub/app/get-version-required-v1", 
		"Method=POST", 
		"Resource=0", 
		"RecContentType=application/json", 
		"Referer=", 
		"Snapshot=t1.inf", 
		"Mode=HTML", 
		"EncType=application/json; charset=utf-8", 
		"Body={\"meta\":{\"appVersion\":\"6.6.0-PR-2248-build-1-DEV\",\"deviceModel\":\"Samsung SM-G973U1\",\"deviceTampered\":false,\"deviceType\":\"phone\",\"lang\":\"en\",\"osName\":\"android\",\"osVersion\":\"9\"},\"request\":{}}", 
		LAST);

	web_add_cookie("PA_S=AQE8; DOMAIN=mcg-api-tst2.unionbank.com");

	web_add_header("Cookie2", 
		"$Version=1");

	web_custom_request("get-app-info-v1", 
		"URL=https://mcg-api-tst2.unionbank.com/m-api/http/pub/app/get-app-info-v1", 
		"Method=POST", 
		"Resource=0", 
		"RecContentType=application/json", 
		"Referer=", 
		"Snapshot=t2.inf", 
		"Mode=HTML", 
		"EncType=application/json; charset=utf-8", 
		"Body={\"meta\":{\"appVersion\":\"6.6.0-PR-2248-build-1-DEV\",\"deviceModel\":\"Samsung SM-G973U1\",\"deviceTampered\":false,\"deviceType\":\"phone\",\"lang\":\"en\",\"osName\":\"android\",\"osVersion\":\"9\"},\"request\":{}}", 
		LAST);

	/*Possible OAUTH authorization was detected. It is recommended to correlate the authorization parameters.*/

	web_add_auto_header("X-TS-Client-Version", 
		"6.0.0 (7427);[1,2,3,6,7,8,10,11,12,14,28,19]");

	web_custom_request("bind", 
		"URL=https://mae-auth-tst2.unionbank.com/api/v2/auth/bind?aid=tab_mobile_app&locale=en-US", 
		"Method=POST", 
		"Resource=0", 
		"RecContentType=application/json", 
		"Referer=", 
		"Snapshot=t3.inf", 
		"Mode=HTML", 
		"EncType=application/json", 
		"Body={\"headers\":[{\"type\":\"uid\",\"uid\":\"harrison21\"}],\"data\":{\"collection_result\":{\"metadata\":{\"scheme_version\":2,\"version\":\"6.0.0 (7427)\",\"timestamp\":1653667659},\"content\":{\"hw_authenticators\":{\"fido\":[{\"aaid\":\"1206#0001\"},{\"aaid\":\"1206#0002\"},{\"aaid\":\"1206#0003\"}],\"device_biometrics\":{\"supported\":false,\"user_registered\":false},\"fingerprint\":{\"supported\":true,\"user_registered\":true},\"face_id\":{\"supported\":false,\"user_registered\":false}},\""
		"device_details\":{\"logged_users\":0,\"persistence_mode\":\"false\",\"hw_type\":\"Phone\",\"wifi_network\":{\"bssid\":\"0f607264fc6318a92b9e13c65db7cd3c\",\"ssid\":\"d9c471b76710fca876003681b785db87\"},\"tampered\":true,\"sim_operator\":\"\",\"roaming\":false,\"master_key_generated\":1653667491022,\"device_id\":\"352338100399656\",\"device_model\":\"samsung/SM-G973U1\",\"tz\":\"America/Phoenix\",\"os_version\":\"9\",\"jailbroken\":false,\"sim_operator_name\":\"\",\"frontal_camera\":true,\""
		"device_name\":\"41663efad80553ba\",\"known_networks\":[{\"ssid\":\"0dcdbfa6e3b9910eed9db8376845acfc\"},{\"ssid\":\"1af5b03569d3a02947732ec3ecb0bdb6\"},{\"ssid\":\"eba99a04b3bdbb397d16da99c73a8bc8\"}],\"has_hw_security\":true,\"screen_lock\":true,\"os_type\":\"Android\",\"sflags\":-1,\"connection\":\"wifi: 1.110.75.10\"},\"installed_packages\":[\"cd30056bb59a3a1569c6a116dc217d5b\",\"694bcd0480ffad1590a21b096c8c041b\",\"eeb13de963e53cc3a9d75b03e2f64a7f\",\"5f3ba939d2041614fc2b4f2050aaef8f\",\""
		"695741e6a892614efa0826bd2b7b8e8b\",\"5f71ced64935cba77f4b29dd98d98dbe\",\"759d342797ad310ff56f8a880909c619\",\"6ed61a638ad994fcc240b4c1186e538e\"],\"capabilities\":{\"fido2_user_verifying_platform_authenticator_available\":true,\"audio_acquisition_supported\":true,\"finger_print_supported\":true,\"image_acquisition_supported\":true,\"persistent_keys_supported\":true,\"face_id_key_bio_protection_supported\":false,\"fido_client_present\":true,\"fido2_client_present\":true,\"dyadic_present\":false,\""
		"installed_plugins\":[],\"host_provided_features\":\"19\"},\"collector_state\":{\"accounts\":\"active\",\"devicedetails\":\"active\",\"contacts\":\"active\",\"owner\":\"active\",\"software\":\"active\",\"location\":\"active\",\"locationcountry\":\"disabled\",\"bluetooth\":\"active\",\"externalsdkdetails\":\"active\",\"hwauthenticators\":\"active\",\"capabilities\":\"active\",\"fidoauthenticators\":\"active\",\"largedata\":\"active\",\"localenrollments\":\"active\",\"devicefingerprint\":\"active\"},"
		"\"local_enrollments\":{}}},\"public_key\":{\"key\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZhbigvF8OYbM/PP2HuVzUuXHu3whlCUoo1aiwqyRRmQDLKD4wJ+rPXbIZMMdnZXKYCKXV0xzoMpx3rPiw+NRHw==\",\"type\":\"ec\"},\"encryption_public_key\":{\"key\":\"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwRUhj1SwnQWAfR+5r63fJ4ELGL9Yg5VrZ2fdXSRGX7L7UlMQOWDs1GeDVYGSRN/JbMjl9P2ArLzdsMAiT6UlVTq+5aWbrl+tnNrXIhTMjuzoKUW70UkhljJ5kP51shWtCBfIX1CB7ru/PPFpU7uJUeZFshqnKl8aTkeL1MbouBvVRZl01JfIGuNFR4pYvKR/SfNpF1SNt2usxcdFDHsWAsmc3MUKWTai"
		"+mmHrOCP+YlPsMKLlK8hfjW1SDCbqZg9w81DZbFaHf2jcxPDhG60dKlLbtlMyk5boMBa59BYtnKjUxfp8H7aztHxGbohAwAI9sJrYPLUPp7lwkRAplwdpQIDAQAB\",\"type\":\"rsa\"},\"params\":{\"tab_app_version\":\"6.6.0-PR-2248-build-1-DEV\",\"raa_device_fingerprint\":\"{\\\"TIMESTAMP\\\":\\\"2022-05-27T16:07:36Z\\\",\\\"TimeZone\\\":\\\"-7.0\\\",\\\"HardwareID\\\":\\\"352338100399656\\\",\\\"DeviceModel\\\":\\\"SM-G973U1\\\",\\\"MultitaskingSupported\\\":true,\\\"DeviceName\\\":\\\"Galaxy S10\\\",\\\"DeviceSystemName\\\":\\\""
		"Android\\\",\\\"DeviceSystemVersion\\\":\\\"28\\\",\\\"Languages\\\":\\\"en\\\",\\\"WiFiMacAddress\\\":\\\"c4:ac:59:17:f7:23\\\",\\\"ScreenSize\\\":\\\"1440x2723\\\",\\\"RSA_ApplicationKey\\\":\\\"43FCAD7BB133E1FFB34F6E63C548AE6F\\\",\\\"OS_ID\\\":\\\"41663efad80553ba\\\",\\\"SDK_VERSION\\\":\\\"4.1\\\",\\\"Compromised\\\":0,\\\"Emulator\\\":0}\",\"shp_telemetry_headers\":\"{\\\"X-4t5NIhMW-z\\\":\\\"q\\\",\\\"X-4t5NIhMW-g\\\":\\\""
		"qFqYbLRxP46lyCuPkp4_NZzr6RRySGNP-iY-b1HSMDurGLZIOquJdw95XCn7EGl8aOwjZV_4TaxxIct3DkvtC7ypTrkFxlMzjxDPXyvZA-B_Mki5UD7RAZOFjKSF1_5S9lBC-mT-m0knVWM7DLNiY13gOJih15RZNNNzR55MA8T4E2Jw_L4ZmkO4KsgPrqgHfktpn-y9QGba_TB8O-TagZJUOfbFXe-YXI3b0O4r14CWy-OuPM63Her66bq9TlMRizawxb3N5dQOPsospcF4JSwvFUwnDeETqvgLFQF4ZVGa1QVyckco4utxt0ENLV0QO5HBS2GwPhukrhjwMlirvnfLVej-z-9aLu3ddyfuWugcBlHUcCPsQfJ1iuFqu0fVVi0AbwBlYQqM1BKLS3T9JnppCnZb97TzyQFqYlHC9cF2uunPtjfsVcV470x7MusgFYcKb0_qNQjNhR5sUbAYjyee5zEemKiqvwGjU_Az4yNZLQ7WmslqAH"
		"I4_GcOGoNSZW85DZgA6LGVgkOKbCYu4Pp2-ZcLFhHC6kD9pTvBhefKeL5jkziqlnskMRZ5GnDtUAEFmcR5YN_TO1zq5JPS1LtflJj-S8v4_64yXV-XgSaWTDYUH6qMGu2JRbAP4PpZVl_--xFr1HCvOLqJQ1hIEnTjoYpbulJEf1CNuGU_p2dTlOe53egpBf6Z_RBH6OBY3gih_AeS-x2fkZLaV6Gv4fAVoH01ZNZLdZY0HXagCWh-xpXWkQfRypscBndck4sWRzNlPMLJOU-lboeFvI9SF23jYtHvrwk7UUYTDVlMsSecbfpAhHYYwkNHh3oLzVO60Afu1pw8UiFOFjH3ObCLS6JmhkhGTlOI7lQszY_L6j-qcIsK4jQaU2BI-bCxkQUP1fMku5zAANE3cwv_5iVmpMG2hKrtwgQxQpuZAIpzgYYMKVcya9mJ4yW9Uz4B9Q8RY36vGalxv9PT-ty-4Nh40BRYJSMM04Tr579AX4udNm61"
		"pcxqI5qYsimOL-36fNFqBUavWd73kgwfNgdtKaE=;L8bsHJK_oSlZegzxpAE6OgjkVLUP0jE7JBPxikkAfZE=;g\\\",\\\"X-4t5NIhMW-f\\\":\\\"A8T531l6AQAA4hOfO7JEVbc9yCQYCwIY3A58JL4Y3XV3JZGCgOprq0OwPaCOAX8AAAGLr4YoMVIAAAAAAAAAAA==\\\",\\\"X-4t5NIhMW-c\\\":\\\"AICS21l6AQAAQHzVEQASN8t9rZq_0HOE5ohblSVfTNIxJqUVZm3-Tb1VFTfh\\\",\\\"X-4t5NIhMW-b\\\":\\\"-21y2fa\\\",\\\"X-4t5NIhMW-e\\\":\\\"b;"
		"NBkFZUzoOyBLphtFGE945QJowSjZj0viv85zs4aBj27Mkz-2jQKzZkYhqIalbbHvwfa6z4P1gJ2v4kRcRAFrUa80wWAzQ_eUpajLzGIGpstDZmpqEfRWO8nlwj4-YvZzcs3XgydoTHcGfADLdWhnJbcOdGbwmW7rwnZGNO1wyW1q6cFq9-ccZp-ZgXTDaSTqATIQWsdyhAsMEWs_TTsX8b2GAT25TGJCdKNT3Dn4SScnFmfkm0zCyQTsqk5IlzrgPDycI8qQt91IMirh6Y3iwEfSeuunRn93NNPIoZaIYU_8yFFBz6PuGpvalPaKzyQuJwEie9xC_vtLc1LctOOHY7KnrnclHvjHPqmdh8YBB3dFp7GZr80izU98UqZVR-mcCzMqsj1m7KlI17F2Z2N_aIb2-kDxmae-NsEASML7rcfrg2GyHNwVtxuXl8Zj5We4xKuvfGwYed9gyGlQtV6N0LqqPHMbyPkaVg6NqSA7AHWvOe21yV7cwl"
		"H_UWCv1lq4bGSvdLt4YL_MFzVYLCaiF_-XXsD7aee85tqN5XKR8hxL9BgGoIMvpxXSD9SV0Upyo_PY4tdd9A0PnwiER0GGfOoILpReNqs3xlxDeJ_rPF1F-4JrNcG5LtE706qaX-kjJwKMfEZHklJrqMA8ARquJ8ycQyZALV3ShD5yty8-I4vX4RrTks-Mtuton_9nUG34SEghylmbtOAM33tdFmxYYWG-CgR3OjyslAx1S1egSShU6UKGncyiPGw0kmj32SXvjpJtH23af2h_H1FJYTi5NInw-OsOojy8hYkwEny-18kvqi2IEe9_qMwvP9g1DZnnzSD_qjw4xzbTqLernPQzTSEOY6VFyuxgEz9kTTnHALWgrUwC3OcY2I7MH7_deKiuHC4E5J-ojNLMLmnv9nYB4AvEs0PcwS0Jx_m7QosVe7lpJN2j2FD9bvRfXaOJVjzBq6UOXnAypqg0lnL2lIlSkfz2An2wPFZzhBD8FS8_B0S-"
		"aJxobIoL52HyWkvloUdnGGBPaET29ZJ8lnyZWIdIsQ-VHX43_ZTvEhY9kpe25t7r9CVtdWLJ3S8212MFhv9h75YcvALELqXv9U0lqewa6GTiefhVYNsM7p8oj3VSjsEttJlFMtyxsN78Va12VZ_vu1krMw3ik8OCQDYozX5lOzKjhvbFuSlsoHOu2ssaeL0BfQDxiojOJMTDVbVnKxJA85BlFR85QH7xL3imXjFvIR4Y-4ZrhPdvOz8SIKhBhPqxomZv;LbQw8UEUYtZagfexicVSrUv0tL3HlyuoWLKy8eMyWsQ=\\\",\\\"X-4t5NIhMW-d\\\":\\\"ABZAkAiQgrIAgACAAoAQ0EKACIGOAG3-Tb1VFTfh_____6wSsfQCsezVj9DOwQaLTA847T3s_g\\\",\\\"X-4t5NIhMW-a\\\":\\\""
		"ihnCbX2s1CWBt2ciJKukGMLCqrF_qKF0eoFb4rh-HHqExC5bPUrqbnd_UtM2raY10a8RMbXg6CNIFqcEfyZF=2IqEfSEza_dn-lGI9qYtRx2e_Sc-zdc_avzh3fR=MKhRMqUOjO4PRHjdJMrysJ-VCbG=K9_oaT6pD5Zr1ax273M13g-Db_gW_-dvr3sSXM3JNHIKX5H0gs=HCbUalzgBJB_HXra_0ODYDkoL2BGGTR4NR0-d5iQOdIYliLv1Z0SMpmJHXDyx9JDO=ULqxmNWitr=aLi9m7FB9ISs0GdTTGIkiGZ-4QPttmWDzpABCk-v5c4YaW_hXrZP8EeSCqRGQJqUc3mlM_LC45ZJEb8dWRAfY4TgZlVdE7EW8g8Dctlo_q_ejUPc=tVoC6y2WZYJmaM9v0qyrhqfTWrJkxLmDzDsSQBbedxkhbibEUJ5_vvSyjXL=bBYsFzv-I2AoYW6Ixu="
		"TT4AgXaud5zLkJoHRt6Q_-zq7BLUIU7kB_U6DVTIT-uJA=z7dLnBLdWx6ffvrmx4EqbWUp1-bOltNufjYQ36VgHN_bzlgyMRaauQjG4Qb4mTbHeGfdKsHeY2cVNNWFWI2cbeofPTThB3oFGs0GMEtIENys5WMrzkbO3NYqKWj8Ai2Y1xOmrHYcaOXsTGrUraRfUo0qI9OKJUDcWr-3W8-QRjE16a7NsnLaUM-4fkyI_F9CbWR6C1oKGB5kTH5aPmPggtdaiJMJOL2VMVd_qIio64LsYFE1FZzYUIybUz3djFaH5r9zzxaf=fvqH=52bX1L8gur-POyHf1BNvFeyIcu5Ub7yx5Bd=OY1ulGI4Z0jW8NADudE9aIHcZybCl2qu=PaWTGF=v9s0BYhKQAIUyc15OcOx2EPB="
		"ZmjXQ6GBUQPeBQrWyZx4sojuDIoI_XKaCJiVUox4juNvFCN2yLJK_l3SV647PZ00N5RRdK3_YMtBNz2hnxp0M4TPI9nGAD1mxiVXfu9UHie9tdYYf1gliBVrETcUhBPIh2bu=BNfaS2O_Mk3ZgOjts_XGxM1RWHel9LXbJXeEHVz7TDFCjJEpFbsnYW656p91_R5HzCa6xGFXITCuD7NJB8HHe39ss5lLkJvy7jSGeeiXuY1qIENF5jMQ46FXf_1CIFy7zH7bPIQUCuPQ=TfpF821IWu9_azdpKk6FXn4C_IG2mPN79nt_-mQJu=toRxy3PQPWdt_tGup_yveEPm=rdnYyfMqlu4fG-e3Bd1cWFKEQMRcmNPp=L__6Jb_iXRTci4mxhOLMxrspLB1y_rvPJFzVp55L8RSrQfzgU0GzJ9d_IUZAh_Ey48lqNN4E8-M4PBjQMfSf3DBO-x5-lIg1-ARN37pNzB8M_SY6YrklTQCrZgiba="
		"du9ZpRRKpced7jl1os8bAdhxNn1QgCndhkvMVe1-ChaVEvHoCTlzBB-iPb6XOgZT4nWe4Fc=11dWvHq1r3MIDUEg3TpG0WKoJbZpnx3BAZg_Z=1FfbcL9ebeZYQlhXqk9i6zsJHxBWMU=zRN=yIPyj3KJV=edBJ_qmfL7zbQfhdsyPU8nyhgR72rP=SLZ8A=EXxxrSBQFdKUA2O6VDyJA4RYUKVCkIIUyuWp5a_K=Faa6F8HdehSKM_VIh6qV-TJibbce9Cokz=Tz9EV7tC9VFNAVd4TTPTWTFe8WQrr4YN8GFs5kbbWjaAD33KVqPIqYtd_PCtruIF14Jp0jQsTYOkEBXxT6OinfDbnIu9UClAnzj8Rl7ZdDau7IbR=KSnLHgNY7SJdCJKf1GfbxgvHLR-2yJntt-B="
		"yNdEzyWthWls6zXyXGA60HMOaLKhDnZxOot-WAA_N00JWCpZRrObt2_DES7thIcqSuoQcfZq6vgVF41Igim1kFAVd2vRSnhFK-IU2b7il7kjsokttqOJSTSB9bPId8cVDkLeIRIv51EAd7rTNrIbmRpCbLUy75z5x-XmaJLJDH-EBQ4b3C75DMap587QgkY3QkeiV-zTQWV4Bd=b1LLIhsxXlILxIYUd=kVRYQ9fpmUPTd0nY2h-AN4zhz8T9rf3DfE4_E47rZA=jZA2u78Q2nIvLOl3TfC2E7tmvMRLo0aAiP=IrGqJzK_Tk1VWd242ECRYrFHadpSJO0dQeiA9ZCJ3JxhliY-KPfszmdM4xuPxDTXP3vytguskKPlyxmnvqxKSRUMIM8QkTg0KMCsE0WvgDh_x3GmR_anTzaaAb=NV="
		"mluijkFMSn1bosFPu3K9sOFZUS9S6ZsmjiLb9kdXDR-VzKhzKIndQKvaP3Cj_gufkcCRQXCT80jI7BU88k0OsyBeVCK2mBMxa4p7hlJtJefRrA9FmiituqWA3AfQTMo_N8kM7AkHp6z=Z119i2isc_Vthkn03U6l15TA=oapXjdO7LFDI4rrdhqZOlzxlfSFWn=_I\\\"}\",\"auth_type\":\"PA\"}}}", 
		LAST);

	web_add_header("Content-Signature", 
		"data:MEUCIE4YacXr92PzZuGaGMPeeMx3LpAk33dv3Al8fxXr//Q0AiEAgrVQReg1kdjkfFX+3I6vSWIxzbKsUOOtxT9BmzqlXps=;key-id:081a84885f629dae446b8367c87c85da5c8ce3fc6d0868fd67e95393e08760d2;scheme:4");

	web_custom_request("assert", 
		"URL=https://mae-auth-tst2.unionbank.com/api/v2/auth/assert?aid=tab_mobile_app&did=75bed32e-a9e2-4978-beb0-a839f32858b7&sid=d2bc9127-83e1-4d43-95ab-3d427041c143&locale=en-US", 
		"Method=POST", 
		"Resource=0", 
		"RecContentType=application/json", 
		"Referer=", 
		"Snapshot=t4.inf", 
		"Mode=HTML", 
		"EncType=application/json", 
		"Body={\"headers\":[{\"type\":\"uid\",\"uid\":\"harrison21\"}],\"data\":{\"action\":\"authentication\",\"assert\":\"authenticate\",\"assertion_id\":\"bqsx6MVS5Vw3SbNpDQh+L7CV\",\"fch\":\"pPuJYy6045jsGtLXGzoa4ndQ\",\"data\":{\"password\":\"Test1234\"},\"method\":\"password\"}}", 
		LAST);

	web_add_header("Content-Signature", 
		"data:MEUCIA9/sMW3YNPuBoFYv+AzvYzzaSC3Xlqvzm24GeNp9WcSAiEAmj0OscA2YHpEoYdguKCrRpSu3bltJihvQqdFLc4C5RM=;key-id:081a84885f629dae446b8367c87c85da5c8ce3fc6d0868fd67e95393e08760d2;scheme:4");

	web_custom_request("assert_2", 
		"URL=https://mae-auth-tst2.unionbank.com/api/v2/auth/assert?aid=tab_mobile_app&did=75bed32e-a9e2-4978-beb0-a839f32858b7&sid=d2bc9127-83e1-4d43-95ab-3d427041c143&locale=en-US", 
		"Method=POST", 
		"Resource=0", 
		"RecContentType=application/json", 
		"Referer=", 
		"Snapshot=t5.inf", 
		"Mode=HTML", 
		"EncType=application/json", 
		"Body={\"headers\":[{\"type\":\"uid\",\"uid\":\"harrison21\"}],\"data\":{\"action\":\"form\",\"assert\":\"action\",\"assertion_id\":\"nTzN6FWooM2/so/EW3cXBlpm\",\"fch\":\"pPuJYy6045jsGtLXGzoa4ndQ\",\"input\":{\"scq_answer_text\":\"in\",\"scq_question_id\":\"68\"}}}", 
		LAST);

	web_revert_auto_header("X-TS-Client-Version");

	web_add_auto_header("Cookie2", 
		"$Version=1");

	web_add_header("Transmit-xsmid", 
		"4e48c685-9b0e-4cc3-a072-955ee49f4379");

	web_custom_request("post-login-v3", 
		"URL=https://mcg-api-tst2.unionbank.com/m-api/http/sec/auth/post-login-v3", 
		"Method=POST", 
		"Resource=0", 
		"RecContentType=application/json", 
		"Referer=", 
		"Snapshot=t6.inf", 
		"Mode=HTML", 
		"EncType=application/json; charset=utf-8", 
		"Body={\"challengeRequest\":{},\"meta\":{\"appVersion\":\"6.6.0-PR-2248-build-1-DEV\",\"deviceModel\":\"Samsung SM-G973U1\",\"deviceTampered\":false,\"deviceType\":\"phone\",\"lang\":\"en\",\"osName\":\"android\",\"osVersion\":\"9\"},\"request\":{}}", 
		LAST);

	web_add_cookie("MCG-USER=harrison21; DOMAIN=mcg-api-tst2.unionbank.com");

	web_custom_request("check-enrollment-eligibility-v1", 
		"URL=https://mcg-api-tst2.unionbank.com/m-api/http/sec/sauth/check-enrollment-eligibility-v1", 
		"Method=POST", 
		"Resource=0", 
		"RecContentType=application/json", 
		"Referer=", 
		"Snapshot=t7.inf", 
		"Mode=HTML", 
		"EncType=application/json; charset=utf-8", 
		"Body={\"meta\":{\"appVersion\":\"6.6.0-PR-2248-build-1-DEV\",\"deviceModel\":\"Samsung SM-G973U1\",\"deviceTampered\":false,\"deviceType\":\"phone\",\"lang\":\"en\",\"osName\":\"android\",\"osVersion\":\"9\"},\"request\":{\"deviceModelName\":\"Samsung SM-G973U1\",\"deviceOSName\":\"ANDROID\",\"deviceOSVersion\":\"9\",\"strongAuthMethod\":\"FINGERPRINT\",\"bankingUserType\":\"OLB\"}}", 
		LAST);

	web_custom_request("get-alert-count-v1", 
		"URL=https://mcg-api-tst2.unionbank.com/m-api/http/sec/alert/get-alert-count-v1", 
		"Method=POST", 
		"Resource=0", 
		"RecContentType=application/json", 
		"Referer=", 
		"Snapshot=t8.inf", 
		"Mode=HTML", 
		"EncType=application/json; charset=utf-8", 
		"Body={\"challengeRequest\":{},\"meta\":{\"appVersion\":\"6.6.0-PR-2248-build-1-DEV\",\"deviceModel\":\"Samsung SM-G973U1\",\"deviceTampered\":false,\"deviceType\":\"phone\",\"lang\":\"en\",\"osName\":\"android\",\"osVersion\":\"9\"},\"request\":{\"alertQueryType\":\"PENDING_ACTION_ALERT\",\"bankingUserType\":\"OLB\"}}", 
		LAST);

	web_custom_request("get-acct-list-v1", 
		"URL=https://mcg-api-tst2.unionbank.com/m-api/http/sec/acct/get-acct-list-v1", 
		"Method=POST", 
		"Resource=0", 
		"RecContentType=application/json", 
		"Referer=", 
		"Snapshot=t9.inf", 
		"Mode=HTML", 
		"EncType=application/json; charset=utf-8", 
		"Body={\"challengeRequest\":{},\"meta\":{\"appVersion\":\"6.6.0-PR-2248-build-1-DEV\",\"deviceModel\":\"Samsung SM-G973U1\",\"deviceTampered\":false,\"deviceType\":\"phone\",\"lang\":\"en\",\"osName\":\"android\",\"osVersion\":\"9\"},\"request\":{\"bankingUserType\":\"OLB\",\"includeMSPFlag\":false,\"includeNFSFlag\":false,\"includeUCLFlag\":false,\"isSupportCCForIBB\":true}}", 
		LAST);

	web_custom_request("get-user-profile-v1", 
		"URL=https://mcg-api-tst2.unionbank.com/m-api/http/sec/user/get-user-profile-v1", 
		"Method=POST", 
		"Resource=0", 
		"RecContentType=application/json", 
		"Referer=", 
		"Snapshot=t10.inf", 
		"Mode=HTML", 
		"EncType=application/json; charset=utf-8", 
		"Body={\"challengeRequest\":{},\"meta\":{\"appVersion\":\"6.6.0-PR-2248-build-1-DEV\",\"deviceModel\":\"Samsung SM-G973U1\",\"deviceTampered\":false,\"deviceType\":\"phone\",\"lang\":\"en\",\"osName\":\"android\",\"osVersion\":\"9\"},\"request\":{\"bankingUserType\":\"OLB\",\"supportCardServiceForIBB\":true}}", 
		LAST);

	web_custom_request("get-marketing-content-v1", 
		"URL=https://mcg-api-tst2.unionbank.com/m-api/http/pub/app/get-marketing-content-v1", 
		"Method=POST", 
		"Resource=0", 
		"RecContentType=application/json", 
		"Referer=", 
		"Snapshot=t11.inf", 
		"Mode=HTML", 
		"EncType=application/json; charset=utf-8", 
		"Body={\"meta\":{\"appVersion\":\"6.6.0-PR-2248-build-1-DEV\",\"deviceModel\":\"Samsung SM-G973U1\",\"deviceTampered\":false,\"deviceType\":\"phone\",\"lang\":\"en\",\"osName\":\"android\",\"osVersion\":\"9\"},\"request\":{\"bankingUserSegmentType\":\"PRIORITY\",\"bankingUserType\":\"OLB\",\"contentLocale\":{\"regionCode\":\"S_CA\"},\"contentType\":\"BACKGROUND\"}}", 
		LAST);

	web_custom_request("get-pending-transfer-list-v1", 
		"URL=https://mcg-api-tst2.unionbank.com/m-api/http/sec/transfer/get-pending-transfer-list-v1", 
		"Method=POST", 
		"Resource=0", 
		"RecContentType=application/json", 
		"Referer=", 
		"Snapshot=t12.inf", 
		"Mode=HTML", 
		"EncType=application/json; charset=utf-8", 
		"Body={\"challengeRequest\":{},\"meta\":{\"appVersion\":\"6.6.0-PR-2248-build-1-DEV\",\"deviceModel\":\"Samsung SM-G973U1\",\"deviceTampered\":false,\"deviceType\":\"phone\",\"lang\":\"en\",\"osName\":\"android\",\"osVersion\":\"9\"},\"request\":{\"bankingUserType\":\"OLB\"}}", 
		LAST);

	web_revert_auto_header("Cookie2");

	web_add_header("Content-Signature", 
		"data:MEQCIAXRQRBry6y+rGGAhQzTquklwaL82F1kI+P5b1oNOz/aAiAgD0+xcvhW17Xr+US1DJwBr+5I4zLg/15y0oKRkcIE9Q==;key-id:081a84885f629dae446b8367c87c85da5c8ce3fc6d0868fd67e95393e08760d2;scheme:4");

	web_add_header("X-TS-Client-Version", 
		"6.0.0 (7427);[1,2,3,6,7,8,10,11,12,14,28,19]");

	web_custom_request("logout", 
		"URL=https://mae-auth-tst2.unionbank.com/api/v2/auth/logout?aid=tab_mobile_app&did=75bed32e-a9e2-4978-beb0-a839f32858b7&sid=d2bc9127-83e1-4d43-95ab-3d427041c143&locale=en-US", 
		"Method=POST", 
		"Resource=0", 
		"RecContentType=application/json", 
		"Referer=", 
		"Snapshot=t13.inf", 
		"Mode=HTML", 
		"EncType=application/json", 
		"Body={\"headers\":[{\"type\":\"uid\",\"uid\":\"harrison21\"}],\"data\":{}}", 
		LAST);

	web_add_auto_header("Cookie2", 
		"$Version=1");

	web_custom_request("logout-v1", 
		"URL=https://mcg-api-tst2.unionbank.com/m-api/http/sec/auth/logout-v1", 
		"Method=POST", 
		"Resource=0", 
		"RecContentType=application/json", 
		"Referer=", 
		"Snapshot=t14.inf", 
		"Mode=HTML", 
		"EncType=application/json; charset=utf-8", 
		"Body={\"challengeRequest\":{},\"meta\":{\"appVersion\":\"6.6.0-PR-2248-build-1-DEV\",\"deviceModel\":\"Samsung SM-G973U1\",\"deviceTampered\":false,\"deviceType\":\"phone\",\"lang\":\"en\",\"osName\":\"android\",\"osVersion\":\"9\"},\"request\":{}}", 
		LAST);

	web_add_cookie("MCG-USER=harrison21; DOMAIN=oa2-auth-tst2.unionbank.com");

	web_custom_request("startSLO.ping", 
		"URL=https://oa2-auth-tst2.unionbank.com/idp/startSLO.ping", 
		"Method=GET", 
		"Resource=0", 
		"RecContentType=text/html", 
		"Referer=", 
		"Snapshot=t15.inf", 
		"Mode=HTML", 
		LAST);

	web_custom_request("revoke_token.oauth2", 
		"URL=https://oa2-auth-tst2.unionbank.com/as/revoke_token.oauth2", 
		"Method=POST", 
		"Resource=0", 
		"RecContentType=text/html", 
		"Referer=", 
		"Snapshot=t16.inf", 
		"Mode=HTML", 
		"Body=&token_type_hint=access_token&client_id=retailmobileclient&token=0004LAYtrKi7WQgvMi9yx2ZAUC9f", 
		LAST);

	return 0;
}
