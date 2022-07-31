
int transmit_init(char *str, char* str1);
char pem_str_public[2096];
char pem_str_private[2098];
char requestBody[9999];
char contentSignature[1555];
char test[22] = "Hello World!";
int test_out_len = 64;
char test_out[264];
char test_out2[3266];
char body[9999];
char path[256], urlPath[256];
char *currentFolder = "C:\\Users\\jagat_brahma\\git\\loadtestingsdk\\c\\WebHttpHtml1\\";
char *baseUrl = "https://jagat.tsdemo.transmit-field.com";
//char *params1 = "{\"tab_app_version\": \"6.6.0-PR-2248-build-1-DEV\",\"raa_device_fingerprint\": \"{\\\"TIMESTAMP\\\":\\\"2022-05-27T16:07:36Z\\\",\\\"TimeZone\\\":\\\"-7.0\\\",\\\"HardwareID\\\":\\\"352338100399656\\\",\\\"DeviceModel\\\":\\\"SM-G973U1\\\",\\\"MultitaskingSupported\\\":true,\\\"DeviceName\\\":\\\"Galaxy S10\\\",\\\"DeviceSystemName\\\":\\\"Android\",\\\"DeviceSystemVersion\\\":\\\"28\\\",\\\"Languages\\\":\\\"en\\\",\\\"WiFiMacAddress\\\":\\\"c4:ac:59:17:f7:23\\\",\\\"ScreenSize\\\":\\\"1440x2723\\\",\\\"RSA_ApplicationKey\\\":\\\"43FCAD7BB133E1FFB34F6E63C548AE6F\\\",\\\"OS_ID\\\":\\\"41663efad80553ba\\\",\\\"SDK_VERSION\\\":\\\"4.1\\\",\\\"Compromised\\\":0,\\\"Emulator\\\":0}\",\\\"shp_telemetry_headers\\\": \\\"{\\\"X-4t5NIhMW-z\\\":\\\"q\\\",\\\"X-4t5NIhMW-g\\\":\\\"qFqYbLRxP46lyCuPkp4_NZzr6RRySGNP-iY-b1HSMDurGLZIOquJdw95XCn7EGl8aOwjZV_4TaxxIct3DkvtC7ypTrkFxlMzjxDPXyvZA-B_Mki5UD7RAZOFjKSF1_5S9lBC-mT-m0knVWM7DLNiY13gOJih15RZNNNzR55MA8T4E2Jw_L4ZmkO4KsgPrqgHfktpn-y9QGba_TB8O-TagZJUOfbFXe-YXI3b0O4r14CWy-OuPM63Her66bq9TlMRizawxb3N5dQOPsospcF4JSwvFUwnDeETqvgLFQF4ZVGa1QVyckco4utxt0ENLV0QO5HBS2GwPhukrhjwMlirvnfLVej-z-9aLu3ddyfuWugcBlHUcCPsQfJ1iuFqu0fVVi0AbwBlYQqM1BKLS3T9JnppCnZb97TzyQFqYlHC9cF2uunPtjfsVcV470x7MusgFYcKb0_qNQjNhR5sUbAYjyee5zEemKiqvwGjU_Az4yNZLQ7WmslqAHI4_GcOGoNSZW85DZgA6LGVgkOKbCYu4Pp2-ZcLFhHC6kD9pTvBhefKeL5jkziqlnskMRZ5GnDtUAEFmcR5YN_TO1zq5JPS1LtflJj-S8v4_64yXV-XgSaWTDYUH6qMGu2JRbAP4PpZVl_--xFr1HCvOLqJQ1hIEnTjoYpbulJEf1CNuGU_p2dTlOe53egpBf6Z_RBH6OBY3gih_AeS-x2fkZLaV6Gv4fAVoH01ZNZLdZY0HXagCWh-xpXWkQfRypscBndck4sWRzNlPMLJOU-lboeFvI9SF23jYtHvrwk7UUYTDVlMsSecbfpAhHYYwkNHh3oLzVO60Afu1pw8UiFOFjH3ObCLS6JmhkhGTlOI7lQszY_L6j-qcIsK4jQaU2BI-bCxkQUP1fMku5zAANE3cwv_5iVmpMG2hKrtwgQxQpuZAIpzgYYMKVcya9mJ4yW9Uz4B9Q8RY36vGalxv9PT-ty-4Nh40BRYJSMM04Tr579AX4udNm61pcxqI5qYsimOL-36fNFqBUavWd73kgwfNgdtKaE=;L8bsHJK_oSlZegzxpAE6OgjkVLUP0jE7JBPxikkAfZE=;g\\\",\\\"X-4t5NIhMW-f\\\":\\\"A8T531l6AQAA4hOfO7JEVbc9yCQYCwIY3A58JL4Y3XV3JZGCgOprq0OwPaCOAX8AAAGLr4YoMVIAAAAAAAAAAA==\\\",\\\"X-4t5NIhMW-c\\\":\\\"AICS21l6AQAAQHzVEQASN8t9rZq_0HOE5ohblSVfTNIxJqUVZm3-Tb1VFTfh\\\",\\\"X-4t5NIhMW-b\\\":\\\"-21y2fa\\\",\\\"X-4t5NIhMW-e\\\":\\\"b;NBkFZUzoOyBLphtFGE945QJowSjZj0viv85zs4aBj27Mkz-2jQKzZkYhqIalbbHvwfa6z4P1gJ2v4kRcRAFrUa80wWAzQ_eUpajLzGIGpstDZmpqEfRWO8nlwj4-YvZzcs3XgydoTHcGfADLdWhnJbcOdGbwmW7rwnZGNO1wyW1q6cFq9-ccZp-ZgXTDaSTqATIQWsdyhAsMEWs_TTsX8b2GAT25TGJCdKNT3Dn4SScnFmfkm0zCyQTsqk5IlzrgPDycI8qQt91IMirh6Y3iwEfSeuunRn93NNPIoZaIYU_8yFFBz6PuGpvalPaKzyQuJwEie9xC_vtLc1LctOOHY7KnrnclHvjHPqmdh8YBB3dFp7GZr80izU98UqZVR-mcCzMqsj1m7KlI17F2Z2N_aIb2-kDxmae-NsEASML7rcfrg2GyHNwVtxuXl8Zj5We4xKuvfGwYed9gyGlQtV6N0LqqPHMbyPkaVg6NqSA7AHWvOe21yV7cwlH_UWCv1lq4bGSvdLt4YL_MFzVYLCaiF_-XXsD7aee85tqN5XKR8hxL9BgGoIMvpxXSD9SV0Upyo_PY4tdd9A0PnwiER0GGfOoILpReNqs3xlxDeJ_rPF1F-4JrNcG5LtE706qaX-kjJwKMfEZHklJrqMA8ARquJ8ycQyZALV3ShD5yty8-I4vX4RrTks-Mtuton_9nUG34SEghylmbtOAM33tdFmxYYWG-CgR3OjyslAx1S1egSShU6UKGncyiPGw0kmj32SXvjpJtH23af2h_H1FJYTi5NInw-OsOojy8hYkwEny-18kvqi2IEe9_qMwvP9g1DZnnzSD_qjw4xzbTqLernPQzTSEOY6VFyuxgEz9kTTnHALWgrUwC3OcY2I7MH7_deKiuHC4E5J-ojNLMLmnv9nYB4AvEs0PcwS0Jx_m7QosVe7lpJN2j2FD9bvRfXaOJVjzBq6UOXnAypqg0lnL2lIlSkfz2An2wPFZzhBD8FS8_B0S-aJxobIoL52HyWkvloUdnGGBPaET29ZJ8lnyZWIdIsQ-VHX43_ZTvEhY9kpe25t7r9CVtdWLJ3S8212MFhv9h75YcvALELqXv9U0lqewa6GTiefhVYNsM7p8oj3VSjsEttJlFMtyxsN78Va12VZ_vu1krMw3ik8OCQDYozX5lOzKjhvbFuSlsoHOu2ssaeL0BfQDxiojOJMTDVbVnKxJA85BlFR85QH7xL3imXjFvIR4Y-4ZrhPdvOz8SIKhBhPqxomZv;LbQw8UEUYtZagfexicVSrUv0tL3HlyuoWLKy8eMyWsQ=\\\",\\\"X-4t5NIhMW-d\\\":\\\"ABZAkAiQgrIAgACAAoAQ0EKACIGOAG3-Tb1VFTfh_____6wSsfQCsezVj9DOwQaLTA847T3s_g\\\",\\\"X-4t5NIhMW-a\\\":\\\"ihnCbX2s1CWBt2ciJKukGMLCqrF_qKF0eoFb4rh-HHqExC5bPUrqbnd_UtM2raY10a8RMbXg6CNIFqcEfyZF=2IqEfSEza_dn-lGI9qYtRx2e_Sc-zdc_avzh3fR=MKhRMqUOjO4PRHjdJMrysJ-VCbG=K9_oaT6pD5Zr1ax273M13g-Db_gW_-dvr3sSXM3JNHIKX5H0gs=HCbUalzgBJB_HXra_0ODYDkoL2BGGTR4NR0-d5iQOdIYliLv1Z0SMpmJHXDyx9JDO=ULqxmNWitr=aLi9m7FB9ISs0GdTTGIkiGZ-4QPttmWDzpABCk-v5c4YaW_hXrZP8EeSCqRGQJqUc3mlM_LC45ZJEb8dWRAfY4TgZlVdE7EW8g8Dctlo_q_ejUPc=tVoC6y2WZYJmaM9v0qyrhqfTWrJkxLmDzDsSQBbedxkhbibEUJ5_vvSyjXL=bBYsFzv-I2AoYW6Ixu=TT4AgXaud5zLkJoHRt6Q_-zq7BLUIU7kB_U6DVTIT-uJA=z7dLnBLdWx6ffvrmx4EqbWUp1-bOltNufjYQ36VgHN_bzlgyMRaauQjG4Qb4mTbHeGfdKsHeY2cVNNWFWI2cbeofPTThB3oFGs0GMEtIENys5WMrzkbO3NYqKWj8Ai2Y1xOmrHYcaOXsTGrUraRfUo0qI9OKJUDcWr-3W8-QRjE16a7NsnLaUM-4fkyI_F9CbWR6C1oKGB5kTH5aPmPggtdaiJMJOL2VMVd_qIio64LsYFE1FZzYUIybUz3djFaH5r9zzxaf=fvqH=52bX1L8gur-POyHf1BNvFeyIcu5Ub7yx5Bd=OY1ulGI4Z0jW8NADudE9aIHcZybCl2qu=PaWTGF=v9s0BYhKQAIUyc15OcOx2EPB=ZmjXQ6GBUQPeBQrWyZx4sojuDIoI_XKaCJiVUox4juNvFCN2yLJK_l3SV647PZ00N5RRdK3_YMtBNz2hnxp0M4TPI9nGAD1mxiVXfu9UHie9tdYYf1gliBVrETcUhBPIh2bu=BNfaS2O_Mk3ZgOjts_XGxM1RWHel9LXbJXeEHVz7TDFCjJEpFbsnYW656p91_R5HzCa6xGFXITCuD7NJB8HHe39ss5lLkJvy7jSGeeiXuY1qIENF5jMQ46FXf_1CIFy7zH7bPIQUCuPQ=TfpF821IWu9_azdpKk6FXn4C_IG2mPN79nt_-mQJu=toRxy3PQPWdt_tGup_yveEPm=rdnYyfMqlu4fG-e3Bd1cWFKEQMRcmNPp=L__6Jb_iXRTci4mxhOLMxrspLB1y_rvPJFzVp55L8RSrQfzgU0GzJ9d_IUZAh_Ey48lqNN4E8-M4PBjQMfSf3DBO-x5-lIg1-ARN37pNzB8M_SY6YrklTQCrZgiba=du9ZpRRKpced7jl1os8bAdhxNn1QgCndhkvMVe1-ChaVEvHoCTlzBB-iPb6XOgZT4nWe4Fc=11dWvHq1r3MIDUEg3TpG0WKoJbZpnx3BAZg_Z=1FfbcL9ebeZYQlhXqk9i6zsJHxBWMU=zRN=yIPyj3KJV=edBJ_qmfL7zbQfhdsyPU8nyhgR72rP=SLZ8A=EXxxrSBQFdKUA2O6VDyJA4RYUKVCkIIUyuWp5a_K=Faa6F8HdehSKM_VIh6qV-TJibbce9Cokz=Tz9EV7tC9VFNAVd4TTPTWTFe8WQrr4YN8GFs5kbbWjaAD33KVqPIqYtd_PCtruIF14Jp0jQsTYOkEBXxT6OinfDbnIu9UClAnzj8Rl7ZdDau7IbR=KSnLHgNY7SJdCJKf1GfbxgvHLR-2yJntt-B=yNdEzyWthWls6zXyXGA60HMOaLKhDnZxOot-WAA_N00JWCpZRrObt2_DES7thIcqSuoQcfZq6vgVF41Igim1kFAVd2vRSnhFK-IU2b7il7kjsokttqOJSTSB9bPId8cVDkLeIRIv51EAd7rTNrIbmRpCbLUy75z5x-XmaJLJDH-EBQ4b3C75DMap587QgkY3QkeiV-zTQWV4Bd=b1LLIhsxXlILxIYUd=kVRYQ9fpmUPTd0nY2h-AN4zhz8T9rf3DfE4_E47rZA=jZA2u78Q2nIvLOl3TfC2E7tmvMRLo0aAiP=IrGqJzK_Tk1VWd242ECRYrFHadpSJO0dQeiA9ZCJ3JxhliY-KPfszmdM4xuPxDTXP3vytguskKPlyxmnvqxKSRUMIM8QkTg0KMCsE0WvgDh_x3GmR_anTzaaAb=NV=mluijkFMSn1bosFPu3K9sOFZUS9S6ZsmjiLb9kdXDR-VzKhzKIndQKvaP3Cj_gufkcCRQXCT80jI7BU88k0OsyBeVCK2mBMxa4p7hlJtJefRrA9FmiituqWA3AfQTMo_N8kM7AkHp6z=Z119i2isc_Vthkn03U6l15TA=oapXjdO7LFDI4rrdhqZOlzxlfSFWn=_I\\\"}\",\"auth_type\": \"PA\"}";
char *params = "{\"authType\": \"PA\"}";
int transmit_bind(char * userId, char * clientVersion, int scheme, char * appId, char * params, char *path, char * body, char * contentSignature, char * debugString);
void base64decode (const void *b64_decode_this, int decode_this_many_bytes, char *decoded, int * outlen);
void base64encode (const void *b64_encode_this, int encode_this_many_bytes, char *outbuf, int *outlen);
void getSha256(char * inbuf, int inlen, char * outbuf, int *outlen);
void byteArrayToHexString(char * byteArray, int inlen, char * hexString);
void transmit_preProcess(char * path, char * body, char * clientVersion, char * deviceId, int scheme, char* contentSignature, char * debugString);
int  transmit_processSuccessResponse(char * response, char * key, char * value, char *debugString);


char * testSuccessResponse = "{\"error_code\":0,\"error_message\":\"\",\"data\":{\"data\":{\"scq_answer_text\":\"home\"},\"state\":\"completed\",\"application_data\":{\"pending_approvals\":false},\"assertions_complete\":true,\"token\":\"eyJraWQiOiJ7XCJwcm92aWRlcl90eXBlXCI6XCJkYlwiLFwiYWxpYXNcIjpcIm1hZV9qd3Rfc2lnbmluZ19rZXlcIixcInR5cGVcIjpcImxvY2FsXCIsXCJ2ZXJzaW9uXCI6XCIxXCJ9IiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJoYXJyaXNvbjIxIiwib3AiOiJhdXRoIiwibHZsIjoxLCJkc2lkIjoiMDBiOGQ0MzctNmU5MS00YTI2LWIzYTQtMDc3ZTc4OWY3MDBhIiwib2EyX3BmX2FjY2Vzc190b2tlbiI6IjAwMDROaktESlB3OTgydWNUczl4R1FMZ0tKTXYiLCJpc3MiOiJUUyIsIm1jZ19ocnRfcHJvdGVjdGVkX2VuZHBvaW50cyI6InsnXC9zZWNcL3RyYW5zZmVyXC9leGVjdXRlLXRyYW5zZmVyLXYxJzondGFiX2hydF90cmFuc2Zlcl9leGVjdXRlX3RyYW5zZmVyJywnXC9zZWNcL3BheW1lbnRcL2V4ZWN1dGUtcGF5bWVudC12MSc6J3RhYl9ocnRfcGF5bWVudF9leGVjdXRlX3BheW1lbnQnfSIsInBpZCI6ImRlZmF1bHRfYmluZCIsInNpZCI6ImQ0ZjA4ZTA4LWE2MTYtNDQ0Zi05YWExLTk0Y2ZkZWE3ZjBmNyIsImF1ZCI6InRhYl9tb2JpbGVfYXBwIiwicHZpZCI6ImRlZmF1bHRfdmVyc2lvbiIsImV4cCI6MTY1NTkzMTQwNSwieHNtaWQiOiJlOGZhMjM4Yi1jYjEwLTRkNDUtOTQ2Yy1hODM4YWY4ZmU5MWUiLCJpYXQiOjE2NTU5Mjk2MDUsImp0aSI6ImY4M2UzZjQ4LTM1MzEtNGY4NC05ZTEwLTNkMWNlNWZjMGM2MyIsImRpZCI6ImIxNjU0NDQ0LTg4NDUtNDE2MC1iOWZkLWUwYjUyZTE2MmE0ZSJ9.dcBUP5RSDryhn10H9plyH5aOZI0N9bSWRHPaqAcbnNuk2S8LjUq0Z4vVtJiZHBJPtYlSnelrvPbpvSAp3UV6FapYXQ5tNFB4nc4WUhBM3OF850pkato6IqQRB8H3tpHQgExI2NQTOoIDGIUM4rLY2yYaiHnvsZYRUscTjClmv9vBs3WHusG0AA41SO447VjguilOoyfkGoyaByW7PKTBPXR3HetNNGSu-CmJBV7CglPbjY9XpKEE0ddCysd1FaYp6t-PE8MK4SF3Q4rQLCa12ugIQP2ywao_Bba1nvPVQDyIiK42jk_g-bLQ1LICY9l6Ypw5m21Ue40uZ3j7-vRfSA\"},\"headers\":[{\"device_id\":\"b1654444-8845-4160-b9fd-e0b52e162a4e\",\"type\":\"device_id\"},{\"session_id\":\"00b8d437-6e91-4a26-b3a4-077e789f700a\",\"type\":\"session_id\"}]}";
char * testSuccessResponse = "{\"error_code\":0,\"error_message\":\"\",\"data\":{\"data\":{\"scq_answer_text\":\"college\"},\"state\":\"completed\",\"application_data\":{\"pending_approvals\":false},\"assertions_complete\":true,\"token\":\"eyJraWQiOiJ7XCJwcm92aWRlcl90eXBlXCI6XCJkYlwiLFwiYWxpYXNcIjpcIm1hZV9qd3Rfc2lnbmluZ19rZXlcIixcInR5cGVcIjpcImxvY2FsXCIsXCJ2ZXJzaW9uXCI6XCIxXCJ9IiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJwdG11c2VyMDAxIiwib3AiOiJhdXRoIiwibHZsIjoxLCJkc2lkIjoiYWFkZjQzNTItMjE5OS00NWVjLThkZWQtNzVjMWNjNmZkMmQ4Iiwib2EyX3BmX2FjY2Vzc190b2tlbiI6IjAwMDRSZEZ6aFc5TTZZb3k0ZHpFaXJhZGZhM0siLCJpc3MiOiJUUyIsInBpZCI6ImRlZmF1bHRfYmluZCIsInBhcmFtcyI6eyJhdXRoVHlwZSI6IlBBIn0sInNpZCI6ImUxNjM2MTM0LWQyYTQtNGRlOS1hZTBmLWQzZDdkZGI4MjhjMyIsImF1ZCI6ImNtY19tb2JpbGVfYXBwIiwidXNlckFjY2Vzc1Rva2VuIjp7ImZpcnN0TmFtZSI6IkZ1c2VyMDEiLCJsYXN0TmFtZSI6Ikx1c2VyMDEiLCJjdXN0VHlwZSI6IkMiLCJzc29IYXNoSWQiOiJhZmZmNjYzYjMzZTk0MjVmZTA1M2UzOTBhZTBhZDliZiIsImFjY2Vzc1Rva2VuIjoiMDAwNFJkRnpoVzlNNllveTRkekVpcmFkZmEzSyIsImlzTXVmZ0N1c3QiOmZhbHNlLCJ1c2VySWQiOiJwdG11c2VyMDAxIn0sInB2aWQiOiJkZWZhdWx0X3ZlcnNpb24iLCJleHAiOjE2NTczMDYwNTUsInhzbWlkIjoiYjllZTVmMjEtMWRkYy00ZmNhLWIyMTgtZGRjYWQxZGE4OTY5IiwiaWF0IjoxNjU3MzA0MjU1LCJqdGkiOiJkMjUxOWZlZi1hYTE2LTQ3ZDAtOWRhYi1kZjY5ZTNkOWJjYmMiLCJkaWQiOiJkMWM3OTk2MC0xYmVkLTQ2NGUtYmM2Yy02MTk5ODhhMTIyMzIifQ.Td3O8bGDWsU2DWoOlIB7944A5tjEABK49fgze1YqdfIKgKohkPpvRiA_hrdRILeG14IxsBuF1PP6tXVmq7jmY8fmel8_QIZL8WCoz1D57AVmT5f0mWyF8RvbOl-_eOzZlZwWomwk-7dhG6dLfCGsP8JnF2uiMs5-JdNDpjxB5oX88Sc6lM9XO8CbjZEU3WOy00qJTkcgGdUpv9gEcjxkDKxxERzgtqf0raSDPlpLm4sUaP294fUQ6BJWaNs1sLlKRqKjZ3PWsDbDG34B7bV8kd4aEGoScTgC9Snf2n7xrnUoANiU6eEv8TA7GofFD5WmLeW1OXxbEoWMxSYvc1cS3A\"},\"headers\":[{\"device_id\":\"d1c79960-1bed-464e-bc6c-619988a12232\",\"type\":\"device_id\"},{\"session_id\":\"aadf4352-2199-45ec-8ded-75c1cc6fd2d8\",\"type\":\"session_id\"}]}";
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
	char pathToLoad[128];
	
	sprintf(pathToLoad, "%slibcrypto-3.dll", currentFolder);
    rc = lr_load_dll(pathToLoad);
	lr_message("return code = %d", rc);
	
	sprintf(pathToLoad, "%slibssl-3.dll", currentFolder);
    rc = lr_load_dll(pathToLoad);
   
	lr_message("return code = %d", rc);

	sprintf(pathToLoad, "%scjson.dll", currentFolder);
    rc = lr_load_dll(pathToLoad);

	lr_message("return code = %d", rc);

	sprintf(pathToLoad, "%stransmitlib.dll", currentFolder);
    rc = lr_load_dll(pathToLoad);	
	//rc = lr_load_dll("C:\\Users\\jagat_brahma\\git\\loadtestingsdk\\c\\transmitlib\\out\\build\\x86-Debug\\transmitlib.dll");
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
	
	
	rc = transmit_bind(userId, clientVersion, scheme, appId, params, path, body, contentSignature, test_out2);	
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
    sprintf(path,"%s", "/api/v2/auth/bind?aid=mobile&locale=en-US");
	sprintf(urlPath, "URL=%s%s", baseUrl, path);
	web_custom_request("bind", urlPath, 
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
	sprintf(urlPath, "URL=%s%s", baseUrl, path);
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
    
    rc = transmit_processSuccessResponse(testSuccessResponse, "xsmid", test_out2, NULL);
    lr_message("return code from transmit_processSuccessResponse = %d", rc);
    lr_message("value of sub=%s", test_out2);

    rc = transmit_processSuccessResponse(testSuccessResponse, "oa2_pf_access_token", test_out2, NULL);
    lr_message("return code from transmit_processSuccessResponse = %d", rc);
    lr_message("value of sub=%s", test_out2);

    
     
    return 0; 	
    

}

	
