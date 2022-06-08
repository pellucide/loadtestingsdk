package transmitapi
import "net/http"
import "net/http/httptrace"
import "net/http/httputil"
import "crypto"
import "crypto/rsa"
import "crypto/rand"
import "crypto/ecdsa"
import "crypto/elliptic"
import "crypto/sha256"
//import "crypto/sha1"
import "io"
import "io/ioutil"
import "fmt"
import "sort"
import "strings"
import "bytes"
import "math/big"
import "encoding/hex"
import "encoding/asn1"
import "encoding/json"
import "encoding/base64"
import "encoding/binary"
import "errors"
import "crypto/x509"
import "encoding/pem"


//export Transmit
type Transmit struct {
	predefinedVars map[string]string
	headers        map[string]string
	vars           map[string]string
	ecPublicKey    *ecdsa.PublicKey
	ecPrivateKey   *ecdsa.PrivateKey
	rsaPublicKey   *rsa.PublicKey
	rsaPrivateKey  *rsa.PrivateKey
	DATA           string
	HEXDATA        string
    bindBody       string
	scheme         int
    sessions       []string
}

func (rcvr *Transmit) CreateNewSession() {
	rcvr.ecPrivateKey, rcvr.ecPublicKey = rcvr.GenerateEcKeyPair()
	rcvr.rsaPrivateKey, rcvr.rsaPublicKey = rcvr.GenerateRsaKeyPair()
}

//export NewTransmit
func NewTransmit() (rcvr *Transmit) {
	rcvr = &Transmit{}
	rcvr.DATA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890"
	rcvr.HEXDATA = "ABCDEF1234567890"
    rcvr.vars =  make(map[string]string)
    rcvr.CreateNewSession()

    rcvr.predefinedVars =  make(map[string]string)
	rcvr.predefinedVars["url"] = "jagat.tsdemo.transmit-field.com"
	rcvr.predefinedVars["appid"] = "mobile"
	rcvr.predefinedVars["tokenId"] = "mobileeverything"
	rcvr.predefinedVars["tokenValue"] = "6d6c4d9a-b57a-4c07-bbcc-07ce59dd97dc"
	rcvr.predefinedVars["X-TS-Client-Version-6.1.0"] = "6.1.0 (7464);[1,2,3,6,7,8,10,11,12,14,28,19]"

    rcvr.headers =  make(map[string]string)
	rcvr.headers["Content-Type"] = "application/json"
	rcvr.headers["x-ts-client-version"] = rcvr.predefinedVars["X-TS-Client-Version-6.1.0"]
	rcvr.headers["authorization"] = fmt.Sprintf("%v%v%v%v", "TSToken ", rcvr.predefinedVars["tokenValue"], "; tid=", rcvr.predefinedVars["tokenId"])
	rcvr.headers["jmetertest"] = "true"
	rcvr.headers["headerforperftest"] = "false"
    rcvr.scheme = 4
    return
}

func (rcvr *Transmit) GetRandomHexString(length int) (string) {
    retStr := ""
    b := make([]byte, length)
    rand.Read(b)
	for i := 0; i < length; i++ {
		retStr =  retStr + string(rcvr.HEXDATA[int(b[i]) % len(rcvr.HEXDATA)])
	}
	return retStr
}
func (rcvr *Transmit) GetRandomInt() (uint32) {
    b := make([]byte, 4)
    rand.Read(b)
	return binary.BigEndian.Uint32(b)
}
func (rcvr *Transmit) GetRandomLong() (uint64) {
    b := make([]byte, 8)
    rand.Read(b)
	return binary.BigEndian.Uint64(b)
}

func (rcvr *Transmit) GetRandomString(length int) (string) {
    retStr := ""
    b := make([]byte, length)
    rand.Read(b)
	for i := 0; i < length; i++ {
		retStr =  retStr + string(rcvr.DATA[int(b[i]) % len(rcvr.DATA)])
	}
	return retStr
}

func (rcvr *Transmit) GetRsaPrivateKey() (string) {
	return rcvr.GetSessionVar("rsaPrivateKeyEncoded")
}
func (rcvr *Transmit) GetRsaPublicKey() (string) {
	return rcvr.GetSessionVar("rsaPublicKeyEncoded")
}
func (rcvr *Transmit) GetEcPrivateKey() (string) {
	return rcvr.GetSessionVar("ecPrivateKeyEncoded")
}
func (rcvr *Transmit) GetEcPublicKey() (string) {
	return rcvr.GetSessionVar("ecPublicKeyEncoded")
}
func (rcvr *Transmit) GetSessionVar(keyName string) (string) {
	sessionName := rcvr.GetCurrentSession()
	varKeyName := fmt.Sprintf("%v%v", sessionName, keyName)
	return rcvr.vars[varKeyName]
}
func (rcvr *Transmit) GetCurrentSession() (string) {
	return rcvr.vars["currentSesion"]
}
func (rcvr *Transmit) GetUserName() (string) {
	sessionName := rcvr.GetCurrentSession()
	return rcvr.vars[sessionName]
}

func (rcvr *Transmit) LoadEcKeysFromEnv() {
	ecPrivateKeyEncoded := rcvr.GetEcPrivateKey()
	rcvr.ecPrivateKey, _ = ParseEcPrivateKeyFromPemStr(ecPrivateKeyEncoded)
    ecPublicKeyEncoded := rcvr.GetEcPublicKey()
    rcvr.ecPublicKey, _ = ParseEcPublicKeyFromPemStr(ecPublicKeyEncoded)
}

func (rcvr *Transmit) LoadKeysFromEnv() {
	rcvr.LoadEcKeysFromEnv()
	rcvr.LoadRsaKeysFromEnv()
}

func (rcvr *Transmit) LoadRsaKeysFromEnv() {
	privateKeyEncoded := rcvr.GetRsaPrivateKey()
    privateKeyEncodedWithHeader := "\n-----BEGIN " + RsaPrivateKey + "-----\n" +
                                  privateKeyEncoded +
                                  "\n-----END " + RsaPrivateKey + "-----\n"
    rcvr.rsaPrivateKey, _ = ParseRsaPrivateKeyFromPemStr(privateKeyEncodedWithHeader)

	publicKeyEncoded := rcvr.GetRsaPublicKey()
    publicKeyEncodedWithHeader := "\n-----BEGIN " + RsaPublicKey + "-----\n" +
                                  publicKeyEncoded +
                                  "\n-----END " + RsaPublicKey + "-----\n"
	rcvr.rsaPublicKey, _ = ParseRsaPublicKeyFromPemStr(publicKeyEncodedWithHeader)
}

func (rcvr *Transmit) SignRsa(plaintext string) (string, error) {
	rcvr.LoadKeysFromEnv()
	return RsaSign([]byte(plaintext), rcvr.rsaPrivateKey)
}
func (rcvr *Transmit) PutSessionVar(keyName string, value string) {
	sessionName := rcvr.GetCurrentSession()
	varKeyName := fmt.Sprintf("%v%v", sessionName, keyName)
	rcvr.vars[varKeyName] = value
}
func (rcvr *Transmit) PutUserName(userName string) {
	sessionName := rcvr.GetCurrentSession()
	rcvr.vars[sessionName] = userName
}
func (rcvr *Transmit) GetContentSignatureRsa(plaintext string, scheme int) (string) {
	publicKeyEncoded := rcvr.GetRsaPublicKey()
    fmt.Printf("publicKeyEncoded = %s\n", publicKeyEncoded)
    publicKeyEncodedWithHeader := "\n-----BEGIN " + RsaPublicKey + "-----\n" +
                                  publicKeyEncoded +
                                  "\n-----END " + RsaPublicKey + "-----\n"
    publicdata, notDecoded := pem.Decode([]byte(publicKeyEncodedWithHeader))
	if publicdata == nil {
        fmt.Printf("notDecoded = %s\n", notDecoded);
		panic("failed to decode PEM block containing public key")
	}
    keyIdBytes := sha256.Sum256(publicdata.Bytes)
    slice := keyIdBytes[:]
	publicKeyHash := ByteArrayToHexString(slice)
	fmt.Println(fmt.Sprintf("%v%v", "publicKeyHash=", publicKeyHash))
	sig, _ := rcvr.SignRsa(plaintext)
	contentSignature := fmt.Sprintf("%v%v%v%v%v%v", "data:", sig, ";key-id:", publicKeyHash, ";scheme:", scheme)
	if scheme != 4 {
		deviceId := rcvr.GetSessionVar("deviceId")
		contentSignature = fmt.Sprintf("%v%v%v%v%v%v", "data:", sig, ";key-id:", deviceId, ";scheme:", scheme)
	}
	return contentSignature
}

func (rcvr *Transmit) PreProcess(path string, body string, scheme int) {
	rcvr.vars["body"] = body
	rcvr.vars["path"] = path
	clientVersion := rcvr.predefinedVars["X-TS-Client-Version-6.1.0"]
	rcvr.PutSessionVar("body", body)
	plaintext := fmt.Sprintf("%v%v", path, body)
	if scheme == 2 || scheme == 3 || scheme == 4 {
		plaintext = fmt.Sprintf("%v%v%v%v%v", path, "%%", clientVersion, "%%", body)
	}
    fmt.Printf("plaintext=%s\n", plaintext)
	contentSignature := rcvr.GetContentSignatureRsa(plaintext, scheme)
	rcvr.PutSessionVar("contentSignature", contentSignature)
}

func (rcvr *Transmit) Bind() (string, map[string]string, string, string) {

    userId := "jagat"
    publicKey, _ := ExportRsaPublicKeyAsPemStr(rcvr.rsaPublicKey, false)
	clientVersion := rcvr.predefinedVars["X-TS-Client-Version-6.1.0"]
	timestamp := rcvr.vars["timestamp"]

	rcvr.bindBody = fmt.Sprintf("%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v",
    "{ \"data\": { \"collection_result\": { \"metadata\": { \"scheme_version\": ", rcvr.scheme,
    ", \"timestamp\": ", timestamp,
    ", \"version\": \"", clientVersion,
    "\"}, \"content\": { \"accounts\": [{ \"name\": \"", rcvr.GetRandomHexString(32),
    "\",\"type\": \"", rcvr.GetRandomHexString(32),
    "\"},{\"name\": \"b8d2a60277443092b75b9a9f71bce945\",\"type\": \"3330d5072c5971394e189640a9f09b77\" }],",
    "\"capabilities\": {\"audio_acquisition_supported\": true, \"dyadic_present\": true,",
    "\"face_id_key_bio_protection_supported\": false, \"fido_client_present\": true,",
    "\"finger_print_supported\": true, \"host_provided_features\": \"19\", \"image_acquisition_supported\": true,",
    "\"persistent_keys_supported\": true }, \"collector_state\": {",
    "\"accounts\": \"active\", \"bluetooth\": \"active\", \"capabilities\": \"active\",",
    "\"contacts\": \"active\", \"devicedetails\": \"active\", \"externalsdkdetails\": \"active\",",
    "\"fidoauthenticators\": \"disabled\", \"hwauthenticators\": \"active\", \"largedata\": \"disabled\",",
    "\"localenrollments\": \"active\", \"location\": \"active\", \"owner\": \"active\",", " \"software\": \"active\"},",
    "\"contacts\": { \"contacts_count\": 765}, \"device_details\": {\"connection\": \"wifi: 10.103.82.192\",",
    "\"device_id\": \"", rcvr.GetRandomLong(),
    "\", \"device_model\": \"", rcvr.GetRandomString(8),
    "\", \"device_name\": \"", rcvr.GetRandomHexString(15),
    "\", \"frontal_camera\": true, \"has_hw_security\": true, \"hw_type\": \"Phone\", \"jailbroken\": false, \"known_networks\": [",
    "{\"ssid\": \"ab2e79dbba72c3866298b74f1a1c6fa6\"}, {\"secure\": true, \"ssid\": \"4eb341e247478a5a5ec2ba7d755cc614\"",
    "}],", " \"logged_users\": 0,", " \"master_key_generated\": ", rcvr.GetRandomLong(),
    ",\"os_type\": \"Android\", \"os_version\": \"8.0.0\", \"roaming\": false, \"screen_lock\": true, \"sflags\": -1,",
    "\"sim_operator\": \"310410\", \"sim_operator_name\": \"\", \"sim_serial\": \"", rcvr.GetRandomLong(),
    "\" \"subscriber_id\": \"310410035590766\", \"tampered\": true, \"tz\": \"America/New_York\", \"wifi_network\": {",
    "\"bssid\": \"d4705a482b5be4955808176e48f7371e\", \"secure\": true, \"ssid\": \"4eb341e247478a5a5ec2ba7d755cc614\"",
    "}}, \"hw_authenticators\": { \"face_id\": { \"secure\": false, \"supported\": false, \"user_registered\": false",
    "},\"fingerprint\": { \"secure\": true, \"supported\": true, \"user_registered\": true}}, \"installed_packages\": [",
    "\"20c496910ff8da1214ae52d3750684cd\", \"09e5b19fffdd4c9da52742ce536e1d8b\", \"5f5ca4b53bed9c75720d7ae1a8b949fc\",",
    "\"2ce4266d32140417eebea06fd2d5d9cd\", \"40197bd6e7b2b8d5880b666b7a024ab6\"], \"local_enrollments\": {},\"location\": {",
    "\"enabled\": true, \"h_acc\": 12.800999641418457, \"lat\": 40.3528937, \"lng\": -74.4993894},\"owner_details\": {",
    "\"possible_emails\": [ \"f91c98012706e141b2e3bcc286af5e06\"], \"possible_names\": [ \"c3fa673b98c1a9ee6ecc3e38d0381966\"]}}},",
    "\"public_key\": { \"key\": \"", publicKey,
    "\",\"type\": \"rsa\"}, \"encryption_public_key\": { \"key\": \"", publicKey,
    "\", \"type\": \"rsa\"}}, \"headers\": [{ \"type\": \"uid\",\"uid\": \"", userId, "\"}],\"push_token\": \"fakePushToken\"}")

	//userId := rcvr.GetUserName()
	//publicKey := rcvr.GetRsaPublicKey()
	//ecPublicKey := rcvr.GetEcPublicKey()
	appId := rcvr.predefinedVars["appid"]
	//clientVersion := rcvr.predefinedVars["X-TS-Client-Version-6.1.0"]
	//timestamp := rcvr.vars["timestamp"]
	path := fmt.Sprintf("%v%v", "/api/v2/auth/bind?aid=", appId)
	rcvr.vars["body"] = rcvr.bindBody
	rcvr.vars["path"] = path
    rcvr.PreProcess(path, rcvr.bindBody, rcvr.scheme)
	return rcvr.CreatePost(path, rcvr.bindBody)
}

func (rcvr *Transmit) CreatePost(path string, body string) (string, map[string]string, string, string) {
	url := fmt.Sprintf("%v%v%v", "https://", rcvr.predefinedVars["url"], path)
    hdrs := rcvr.headers
    contentSignature := rcvr.GetSessionVar("contentSignature")
	return url, hdrs, body, contentSignature
}
func (rcvr *Transmit) GenerateEcKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey){
	privateKey, publicKey := GenerateEcKeyPair()
	publicKeyEncoded, _ := ExportEcdsaPublicKeyAsPemStr(publicKey, false)
	privateKeyEncoded, _ := ExportEcdsaPrivateKeyAsPemStr(privateKey, false)
	ExportEcdsaPrivateKeyAsPemStr(privateKey, false)
	rcvr.PutSessionVar("ecPublicKeyEncoded", publicKeyEncoded)
	rcvr.PutSessionVar("ecPrivateKeyEncoded", privateKeyEncoded)
    return privateKey, &privateKey.PublicKey
}

func (rcvr *Transmit) GenerateRsaKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, publicKey := GenerateRsaKeyPair(1024)
	publicKeyEncoded, _ :=  ExportRsaPublicKeyAsPemStr(publicKey, false)
	privateKeyEncoded, _ := ExportRsaPrivateKeyAsPemStr(privateKey, false)
	rcvr.PutSessionVar("rsaPublicKeyEncoded", publicKeyEncoded)
	rcvr.PutSessionVar("rsaPrivateKeyEncoded", privateKeyEncoded)
    return privateKey, &privateKey.PublicKey
}

type SignedContentDataPayloadParams struct {
  Title string `json:"title"`
  Text string `json:"text"`
  ContinueButtonText string `json:"continue_button_text"`
  CancelButtonText string `json:"cancel_button_text"`
  Parameters []string `json:"parameters"`
}


type SignedContentDataPayload struct {
  Params SignedContentDataPayloadParams `json:"params"`
  UserInput string `json:"user_input"`
}

type TransmitHeaders []map[string]interface{};

type DeviceAction struct {
  Data DeviceActionInternal `json:"data"`
  //Headers []map[string]interface{} `json:"headers"`
  Headers TransmitHeaders `json:"headers"`
}

var BindUrl = "/api/v2/auth/bind";
var AssertUrl = "/api/v2/auth/assert"

//https://jagatdemo.transmit-test.com:8443/api/v2/mobile/device/action?action=remove&aid=mobile&did=cdcdffca-c974-4648-96e8-d5e95d19f6a9&sid=7f0b7d16-20d1-439c-b0e7-894d5ce5bac2
var DeviceActionUrl = "/api/v2/mobile/device/action"

//"https://jagatdemo.transmit-test.com:8443/api/v2/mobile/devices?aid=mobile&did=cdcdffca-c974-4648-96e8-d5e95d19f6a9&sid=7f0b7d16-20d1-439c-b0e7-894d5ce5bac2"
var DevicesUrl = "/api/v2/mobile/devices"

type DeviceActionInternal struct {
    /*
    https://jagatdemo.transmit-test.com:8443/api/v2/mobile/device/action?action=remove&aid=mobile&did=cdcdffca-c974-4648-96e8-d5e95d19f6a9&sid=7f0b7d16-20d1-439c-b0e7-894d5ce5bac2
    Content-Length: 1944
    X-TS-Client-Version: 4.2.1 (7177);[1,2,3,6,7,8,10,11,12,14,19,27]
    Authorization: TSToken 97d8cbb8-0a9f-4c3e-bfd5-e23826bc0418; tid=mobileeverything
    Content-Signature: data:MEQCIDey1OfMtGcsUcGiEHqLL1xPB1J9C+S031amcbP/AoQzAiA4Ar46nmfPDm/E43uSt3Vp3MuKZtYMCPuz3+kYakof0A==;key-id:cdcdffca-c974-4648-96e8-d5e95d19f6a9;scheme:3
    { "data": {
        "device_id": "357497083990264"
    },
    "headers": [
        {
            "type": "uid",
            "uid": "jagat"
        }
    ]
  }
  */
  DeviceId string `json:"device_id"`
  Name string `json:"name"`
}

type TransmitConfirmation struct {
/*{ "data": {
        "action": "confirmation",
        "assert": "action",
        "assertion_id": "0sExcOk+g2XL28efOQujDxwg",
        "data": {
            "sign_content_data": {
                "payload": "{\"params\":{\"title\":\"Title of information message.\",\"text\":\"Text of information message.\",\"continue_button_text\":\"OK\",\"cancel_button_text\":\"Cancel\",\"parameters\":[]},\"user_input\":\"OK\"}",
                "signed_payload": "MEUCIQC0hirJOccoZ5wQnsGwpC576oryX/ZAqkN2rEt/8ymWNAIgDTshvUz7/AVqKB553N/oi/v+qsQC0ovQtFneq7nv8Kw="
            },
            "user_cancelled": false
        },
        "fch": "iU+pdTy9levSb5Co8F82fSXv"
    },
    "headers": [
        { "type": "uid",
          "uid": "jagat"
        }
    ]
  }*/
  Headers []map[string]interface{} `json:"headers"`
  Data TransmitConfirmationData `json:"data"`
}


type TransmitConfirmationDataData struct {
/*{ "sign_content_data": { "payload": "{\"params\":{\"title\":\"Title of information message.\",\"text\":\"Text of information message.\",\"continue_button_text\":\"OK\",\"cancel_button_text\":\"Cancel\",\"parameters\":[]},\"user_input\":\"OK\"}",
                           "signed_payload": "MEUCIQC0hirJOccoZ5wQnsGwpC576oryX/ZAqkN2rEt/8ymWNAIgDTshvUz7/AVqKB553N/oi/v+qsQC0ovQtFneq7nv8Kw="
     },
     "user_cancelled": false
  } */
  UserCancelled bool `json:"user_cancelled"`
  SignContentData struct {
    Payload string `json:"payload"`
    SignedPayload string `json:"signed_payload"`
  } `json:"sign_content_data"`
}


type TransmitConfirmationData struct {
/*{ "action": "confirmation",
    "assert": "action",
    "assertion_id": "0sExcOk+g2XL28efOQujDxwg",
    "data": {
            "sign_content_data": {
                "payload": "{\"params\":{\"title\":\"Title of information message.\",\"text\":\"Text of information message.\",\"continue_button_text\":\"OK\",\"cancel_button_text\":\"Cancel\",\"parameters\":[]},\"user_input\":\"OK\"}",
                "signed_payload": "MEUCIQC0hirJOccoZ5wQnsGwpC576oryX/ZAqkN2rEt/8ymWNAIgDTshvUz7/AVqKB553N/oi/v+qsQC0ovQtFneq7nv8Kw="
            },
            "user_cancelled": false
    },
    "fch": "iU+pdTy9levSb5Co8F82fSXv"
  } */
  Action string `json:"action"`
  Assert string `json:"assert"`
  AssertionId string `json:"assertion_id"`
  Fch string `json:"fch"`
  Data TransmitConfirmationDataData `json:"data"`
}


type TransmitResponse struct {
/*{  "error_code": 0,
     "error_message": "",
     "headers": [
         { "device_id": "2c5c3223-1885-459e-83e1-48561167654a",
           "type": "device_id"
         },
         { "session_id": "e04aa832-d36a-4c56-aef5-23476f513824",
           "type": "session_id"
         }
     ]
     "data": {
         "assertions_complete": false,
         "challenge": "E5D1oy0ALCaWS6Gkx+4SGbdc",
         "control_flow": [
             { "assertion_id": "Hi6XBmKtWQ1K+cq4XOEd9/Oi",
               "cancel_button_text": "Cancel",
               "continue_button_text": "OK",
               "parameters": [],
               "require_sign_content": true,
               "text": "Text of information message.",
               "title": "Title of information message.",
               "type": "confirmation"
             }
         ],
         "data": null,
         "state": "pending"
     },
  } */
  Headers []map[string]interface{} `json:"headers"`
  ErrorCode int `json:"error_code"`
  ErrorMessage string `json:"error_message"`
  Data TransmitResponseData `json:"data"`
}

type TransmitResponseDataControlFlow struct {
     /*{ "assertions_complete": false,
         "challenge": "E5D1oy0ALCaWS6Gkx+4SGbdc",
         "control_flow": [
             { "assertion_id": "Hi6XBmKtWQ1K+cq4XOEd9/Oi",
               "cancel_button_text": "Cancel",
               "continue_button_text": "OK",
               "parameters": [],
               "require_sign_content": true,
               "text": "Text of information message.",
               "title": "Title of information message.",
               "type": "confirmation"
             }
         ],
         "data": null,
         "state": "pending"
       }*/

  AssertionId string `json:"assertion_id"`
  CancelButtonText string `json:"cancel_button_text"`
  ContinueButtonText string `json:"continue_button_text"`
  RequireSignContent bool `json:"require_sign_content"`
  Text string `json:"text"`
  Title string `json:"title"`
  Type string `json:"type"`
  Parameters []interface{} `json:"parameters"`
}

type TransmitResponseData struct {
  AssertionsComplete bool `json:"assertions_complete"`
  Challenge string `json:"challenge"`
  ControlFlow []TransmitResponseDataControlFlow `json:"control_flow"`
  Data string `json:"data"`
  State string `json:"state"`
}

type Message struct {
  Headers []map[string]interface{} `json:"headers"`
  Data  MessageData `json:"data"`
}

type MessageDataCollectionResultMetadata struct {
  Scheme_version int `json:"scheme_version"`
  Timestamp int64 `json:"timestamp"`
  Version string `json:"version"`
}

type MessageDataCollectionResult struct {
   Content MessageDataCollectionResultContent `json:"content"`
   Metadata MessageDataCollectionResultMetadata `json:"metadata"`
}

type MessageDataCollectionResultContent struct {
   Capabilities MessageDataCollectionResultContentCapabilities `json:"capabilities"`
   Collector_state MessageDataCollectionResultContentCollectorState `json:"collector_state"`
   Contacts MessageDataCollectionResultContentContacts `json:"contacts"`
   Device_detatils MessageDataCollectionResultContentDeviceDetails `json:"device_details"`
   Installed_paclages MessageDataCollectionResultContentInstalledPackages `json:"installed_packages"`
   Hw_authenticators MessageDataCollectionResultContentHwAuthenticators `json:"hw_authenticators"`
   Local_enrollments MessageDataCollectionResultContentLocalEnrollments `json:"local_enrollments"`
   Location MessageDataCollectionResultContentLocation `json:"location"`
}

type MessageDataCollectionResultContentCapabilities struct {
}

type MessageDataCollectionResultContentCollectorState struct {
}

type MessageDataCollectionResultContentDeviceDetails struct {
}

type MessageDataCollectionResultContentInstalledPackages struct {
}

type MessageDataCollectionResultContentHwAuthenticators struct {
}

type MessageDataCollectionResultContentContacts struct {
}

type MessageDataCollectionResultContentLocation struct {
}

type MessageDataCollectionResultContentLocalEnrollments struct {
}

type MessagePublicKey struct {
  Key string `json:"key"`
  Type string `json:"type"`
}

type MessageData struct {
  Public_key MessagePublicKey `json:"public_key"`
  Encryption_public_key MessagePublicKey `json:"encryption_public_key"`
  Collection_result MessageDataCollectionResult `json:"collection_result"`
}

const prime512Bits1 = "10173061325754765131955152269580462509757079141171865951722143511912876572537251277234175925893383239663807027902830711219201024136932081526159511624386047"
const prime512Bits2 = "1403426808204774011246025543849579867757887893075747569136830434889950057636931475858382410762796947674236187658297870554700750976819058193606310115725607"
const primeProduct = "14277146986075436794256131952568608873844141068356858576393716160132189633610701133602714991212450640760828114906256494514089836758057293278892533498140353121497011382626936044058258739703259432600035446175528741212545095361827025828613655759010149932830348297580907318988661275106028271510436712201291405529"

const  EcdsaPublicKey =  "ECDSA PUBLIC KEY";
const  RsaPublicKey   =  "RSA PUBLIC KEY";
const  EcdsaPrivateKey =  "ECDSA PRIVATE KEY";
const  RsaPrivateKey   =  "RSA PRIVATE KEY";
// ErrDecryption represents a failure to decrypt a message.
// It is deliberately vague to avoid adaptive attacks.
var ErrDecryption = errors.New("crypto/rsa: decryption error")

// ErrVerification represents a failure to verify a signature.
// It is deliberately vague to avoid adaptive attacks.
var ErrVerification = errors.New("crypto/rsa: verification error")


var bigZero = big.NewInt(0)
var bigOne = big.NewInt(1)


// decrypt performs an RSA decryption, resulting in a plaintext integer. If a
// random source is given, RSA blinding is used.
func decrypt1(random io.Reader, priv *rsa.PrivateKey, c *big.Int) (m *big.Int, err error) {
	// TODO(agl): can we get away with reusing blinds?
	if c.Cmp(priv.N) > 0 {
		err = ErrDecryption
		return
	}
	if priv.N.Sign() == 0 {
		return nil, ErrDecryption
	}

	var ir *big.Int
	if random != nil {
		//randutil.MaybeReadByte(random)
        var buf [1]byte
		random.Read(buf[:])

		// Blinding enabled. Blinding involves multiplying c by r^e.
		// Then the decryption operation performs (m^e * r^e)^d mod n
		// which equals mr mod n. The factor of r can then be removed
		// by multiplying by the multiplicative inverse of r.

		var r *big.Int
		ir = new(big.Int)
		for {
			r, err = rand.Int(random, priv.N)
			if err != nil {
				return
			}
			if r.Cmp(bigZero) == 0 {
				r = bigOne
			}
			ok := ir.ModInverse(r, priv.N)
			if ok != nil {
				break
			}
		}
		bigE := big.NewInt(int64(priv.E))
		rpowe := new(big.Int).Exp(r, bigE, priv.N) // N != 0
		cCopy := new(big.Int).Set(c)
		cCopy.Mul(cCopy, rpowe)
		cCopy.Mod(cCopy, priv.N)
		c = cCopy
	}

	if priv.Precomputed.Dp == nil {
		m = new(big.Int).Exp(c, priv.D, priv.N)
	} else {
		// We have the precalculated values needed for the CRT.
		m = new(big.Int).Exp(c, priv.Precomputed.Dp, priv.Primes[0])
		m2 := new(big.Int).Exp(c, priv.Precomputed.Dq, priv.Primes[1])
		m.Sub(m, m2)
		if m.Sign() < 0 {
			m.Add(m, priv.Primes[0])
		}
		m.Mul(m, priv.Precomputed.Qinv)
		m.Mod(m, priv.Primes[0])
		m.Mul(m, priv.Primes[1])
		m.Add(m, m2)

		for i, values := range priv.Precomputed.CRTValues {
			prime := priv.Primes[2+i]
			m2.Exp(c, values.Exp, prime)
			m2.Sub(m2, m)
			m2.Mul(m2, values.Coeff)
			m2.Mod(m2, prime)
			if m2.Sign() < 0 {
				m2.Add(m2, prime)
			}
			m2.Mul(m2, values.R)
			m.Add(m, m2)
		}
	}

	if ir != nil {
		// Unblind.
		m.Mul(m, ir)
		m.Mod(m, priv.N)
	}

	return
}



func encrypt1(c *big.Int, pub *rsa.PublicKey, m *big.Int) *big.Int {
	e := big.NewInt(int64(pub.E))
	c.Exp(m, e, pub.N)
	return c
}


func testKeyBasics(priv *rsa.PrivateKey)(error) {
	if err := priv.Validate(); err != nil {
    errorString := fmt.Sprintf("Validate() failed: %s", err)
    err := errors.New(errorString)
		return err
	}
	if priv.D.Cmp(priv.N) > 0 {
    errorString := fmt.Sprintf("private exponent too large")
    err := errors.New(errorString)
		return err
	}

	pub := &priv.PublicKey
	m := big.NewInt(42)
	c := encrypt1(new(big.Int), pub, m)

	m2, err := decrypt1(nil, priv, c)
	if err != nil {
    errorString := fmt.Sprintf("error while decrypting: %s", err)
    err := errors.New(errorString)
		return err
	}
	if m.Cmp(m2) != 0 {
    errorString := fmt.Sprintf("got:%v, want:%v (%+v)", m2, m, priv)
    err := errors.New(errorString)
		return err
	}

	m3, err := decrypt1(rand.Reader, priv, c)
	if err != nil {
    errorString := fmt.Sprintf("error while decrypting (blind): %s", err)
    err := errors.New(errorString)
		return err
	}
	if m.Cmp(m3) != 0 {
    errorString := fmt.Sprintf("(blind) got:%v, want:%v (%#v)", m3, m, priv)
    err := errors.New(errorString)
		return err
	}
		return nil
}


func encrypt(p int, e int, n int) (int64) {
  var encrypted big.Int
  plaintextint := new(big.Int).SetInt64(int64(p))
  moduloint := new(big.Int).SetInt64((int64(n)))
  exponentint := new(big.Int).SetInt64((int64(e)))
  encrypted.Exp(plaintextint, exponentint, moduloint)
  return encrypted.Int64()
  //return int(math.Mod(math.Pow(float64(p), float64(e)), float64(n)))
}

func decrypt(c int64, d int, n int) (int64) {
  var decrypted big.Int
  ciphertextint := new(big.Int).SetInt64(int64(c))
  moduloint := new(big.Int).SetInt64((int64(n)))
  exponentint := new(big.Int).SetInt64((int64(d)))
  decrypted.Exp(ciphertextint, exponentint, moduloint)
  return decrypted.Int64()
  //return int(math.Mod(math.Pow(float64(c), float64(d)), float64(n)))
}


func lcm(temp1 int,temp2 int)(int) {
    var lcmnum int = 1
    if(temp1 > temp2)  {
        lcmnum = temp1
    } else{
        lcmnum = temp2
    }

    for {
        if(lcmnum % temp1 == 0 && lcmnum % temp2 == 0) {    // And operator
          return lcmnum
        }
        lcmnum++
    }
    return temp1 * temp2
}

func gcd(a int, b int)(int){
  if (a == 0) {
    return b
  }
  return gcd(b % a, a)
}

func extendedGcd(a int, b int) (int, int, int) {
   if (a == 0) {
     return b, 0, 1
   }

   gcd, x1, y1 := extendedGcd(b%a, a)
   return gcd, y1 - b/a * x1, x1
}

func moduloInverse(a int, m int) (int, error) {
    t := 0;     newt := 1;
    r := m;     newr := a;
    for (newr != 0) {
        quotient := r / newr
        t, newt = newt, t - quotient * newt
        r, newr = newr, r - quotient * newr
    }
    if (r > 1) {
      return 0, errors.New("a is not invertible")
    }
    if (t < 0) {
      t = t + m
    }
    return t, nil
}


func ExportRsaPrivateKeyAsPemStr(privkey *rsa.PrivateKey, withHeader bool) (string, error) {
  privkey_bytes := x509.MarshalPKCS1PrivateKey(privkey)
  if (withHeader) {
    privkey_pem := pem.EncodeToMemory(
            &pem.Block{
                    Type:  RsaPrivateKey,
                    Bytes: privkey_bytes,
            },
    )
    return string(privkey_pem), nil
  } else {
    return base64.StdEncoding.EncodeToString(privkey_bytes), nil
  }
}

func ParseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
    block, _ := pem.Decode([]byte(privPEM))
    if block == nil {
            return nil, errors.New("failed to parse PEM block containing the key")
    }

    priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
            return nil, err
    }

    return priv, nil
}

func ParseEcPrivateKeyFromPemStr(privPEM string) (*ecdsa.PrivateKey, error) {
    block, _ := pem.Decode([]byte(privPEM))
    if block == nil {
       return nil, errors.New("failed to parse PEM block containing the key")
    }

    priv, err := x509.ParseECPrivateKey(block.Bytes)
    if err != nil {
       return nil, err
    }

    return priv, nil
}

func ExportEcdsaPrivateKeyAsPemStr(privateKey *ecdsa.PrivateKey, withHeader bool) (string, error) {
  privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
  if err != nil {
    return "", err
  }
  if (withHeader) {
    privateKeyPem := pem.EncodeToMemory(
      &pem.Block{
        Type:  EcdsaPrivateKey,
        Bytes: privateKeyBytes,
      },
    )

    return string(privateKeyPem), nil
  } else {
    return base64.StdEncoding.EncodeToString(privateKeyBytes), nil
  }
}

func ExportEcdsaPublicKeyAsPemStr(pubkey *ecdsa.PublicKey, withHeader bool) (string, error) {
  pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubkey)
  if err != nil {
    return "", err
  }
  if (withHeader) {
    pubkey_pem := pem.EncodeToMemory(
      &pem.Block{
        Type:  EcdsaPublicKey,
        Bytes: pubkey_bytes,
      },
    )

    return string(pubkey_pem), nil
  } else {
    return base64.StdEncoding.EncodeToString(pubkey_bytes), nil
  }
}

func ExportRsaPublicKeyAsPemStr(pubkey *rsa.PublicKey, withHeader bool) (string, error) {
    pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubkey)
    if err != nil {
            return "", err
    }
    if (withHeader) {
      pubkey_pem := pem.EncodeToMemory(
        &pem.Block{
          Type:  RsaPublicKey,
          Bytes: pubkey_bytes,
        },
      )

      return string(pubkey_pem), nil
    } else {
      return base64.StdEncoding.EncodeToString(pubkey_bytes), nil
    }
}

func ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
    block, _ := pem.Decode([]byte(pubPEM))
    if block == nil {
            return nil, errors.New("failed to parse PEM block containing the key")
    }

    pub, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
            return nil, err
    }

    switch pub := pub.(type) {
        case *rsa.PublicKey:
            return pub, nil
        default:
            break // fall through
    }
    return nil, errors.New("Key type is not RSA")
}


func ParseEcPublicKeyFromPemStr(pubPEM string) (*ecdsa.PublicKey, error) {
    block, _ := pem.Decode([]byte(pubPEM))
    if block == nil {
       return nil, errors.New("failed to parse PEM block containing the key")
    }

    pub, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
       return nil, err
    }

    switch pub := pub.(type) {
        case *ecdsa.PublicKey:
            return pub, nil
        default:
            break // fall through
    }
    return nil, errors.New("Key type is not RSA")
}



func GenerateRsaKeyPairLocalSmall(p int, q int) (*rsa.PrivateKey, error) {
  n :=  p * q
  //r :=  (p-1) * (q-1)
  totient := lcm(p-1, q-1)
  fmt.Printf("p=%d q=%d n=%d\n",p,q,n)
  fmt.Printf("totient = %d\n", totient)

  e := 2
  for {
    if (e >= totient) {
         errorString := fmt.Sprintf("could not find e between totient=%d and 1\n", totient)
         return nil, errors.New(errorString)
    }
    shouldBe1 := gcd(e, totient)
    fmt.Printf("gcd = %d\n", shouldBe1)
    if (shouldBe1 == 1) {
        break
    }
    e++
  }

  d, err := moduloInverse(e, totient)
  if (err != nil) {
    return nil, err
  }
  d = d + totient
  fmt.Printf("d = %d\n", d)
  fmt.Printf("e = %d\n", e)
  fmt.Printf("encryption key = (%d, %d)\n", e, n)
  fmt.Printf("decryption key = (%d, %d)\n", d, n)

  for m := 2; m < n; m++ {
    c := encrypt(m, e, n)
    m1 := decrypt(c, d, n)
    fmt.Printf("m = %d", m)
    fmt.Printf("    c = %d^%d mod %d =  %d",m, e, n, c)
    fmt.Printf("    m = %d^%d mod %d =  %d\n",c, d, n, m1)
  }

  for _, m := range "Transmit" {
    c := encrypt(int(m), e, n)
    m1 := decrypt(c, d, n)
    fmt.Printf("m = %d", m)
    fmt.Printf("  %c  c = %d^%d mod %d =  %d",m, m, e, n, c)
    fmt.Printf("    m = %d^%d mod %d =  %d\n",c, d, n, m1)
  }

  privateKey := new(rsa.PrivateKey)
  privateKey.PublicKey.E = e //new(big.Int).SetInt64((int64(e)))
  privateKey.PublicKey.N = new(big.Int).SetInt64((int64(n)))
  privateKey.D = new(big.Int).SetInt64((int64(d)))
  primes := make([]*big.Int, 2)
  primes[0] = new(big.Int).SetInt64((int64(p)))
  primes[1] = new(big.Int).SetInt64((int64(q)))
  privateKey.Primes = primes
  privateKey.Precompute()

  err = privateKey.Validate()
  if (err != nil) {
    return nil, err
  }
  err = testKeyBasics(privateKey)
  return privateKey, err
}


func GenerateRsaKeyPairLocalBig() (*rsa.PrivateKey, error) {
  bigOne := big.NewInt(1)
  //p, q := 7, 19
  p := new(big.Int)
  fmt.Sscan(prime512Bits1, p)
  q := new(big.Int)
  fmt.Sscan(prime512Bits2, q)
  n := new(big.Int)
  fmt.Sscan(primeProduct, n)

  n1 := new(big.Int)
  n1.Mul(p, q)

  //r :=  (p-1) * (q-1)
  pminus1 := new(big.Int)
  qminus1 := new(big.Int)
  totient := new(big.Int)
  pminus1.Sub(p, bigOne)
  qminus1.Sub(q, bigOne)
  totient.Mul(pminus1, qminus1)

  e := big.NewInt(65537)
  d := new(big.Int)

  d.ModInverse(e, totient)

  privateKey := new(rsa.PrivateKey)
  privateKey.PublicKey.E = 65537
  privateKey.PublicKey.N = n1
  privateKey.D = d
  primes := make([]*big.Int, 2)
  primes[0] = p
  primes[1] = q
  privateKey.Primes = primes
  privateKey.Precompute()

  err := privateKey.Validate()
  if (err != nil) {
    return nil, err
  }
  err = testKeyBasics(privateKey)
  return privateKey, err
}

func GenerateRsaKeyPair(numberofbits int) (*rsa.PrivateKey, *rsa.PublicKey) {
    privkey, err  := rsa.GenerateKey(rand.Reader, numberofbits)
    CheckError(err)
    return privkey, &privkey.PublicKey
}

func GenerateEcKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
    privkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    CheckError(err)
    return privkey, &privkey.PublicKey
}

func GetClientVersionHeader() string {
  return  "4.1 (6540);[1,2,3,6,7,8,10,11,12,14,19]"
}

func GetTokenValue() string {
  return "97d8cbb8-0a9f-4c3e-bfd5-e23826bc0418"
}

func GetTokenName() string {
  return "mobileeverything"
}


func StringToHexString(payload string)(string) {
  return ByteArrayToHexString([]byte(payload))
}

func ByteArrayToHexString(content []byte)(string) {
	dst := make([]byte, hex.EncodedLen(len(content)))
	hex.Encode(dst, content)
    return string(dst)
}

func CheckError(err error) {
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
        panic(err)
	}
}
type EcdsaSequence struct {
   R, S *big.Int
}

// Sign signs arbitrary data using ECDSA.
func EcdsaSign(data []byte, privkey *ecdsa.PrivateKey) (string, error) {
  //fmt.Printf("=====data to sign =====\n[% d]\n", data)
	// hash message
	hashed1 := sha256.Sum256(data)
  fmt.Printf("hash of data to sign=%x\n",hashed1)

	// sign the hash
	r, s, err := ecdsa.Sign(rand.Reader, privkey, hashed1[:])
	if err != nil {
		return "", err
	}

  //encode into asn1
  ecdsaSequence := EcdsaSequence { r, s }
  encoding, _ := asn1.Marshal(ecdsaSequence)

  //fmt.Printf("type of encoding = %T\n", encoding)
  //fmt.Printf("[% x]",encoding)
  //for _, byteval := range encoding { fmt.Printf("%x ", byteval) }; fmt.Println()

  signatureB64 := base64.StdEncoding.EncodeToString(encoding)
  return signatureB64, nil
}

// Sign signs arbitrary data using RSA.
func RsaSign(data []byte, privkey *rsa.PrivateKey) (string, error) {
    //for _, byteval := range data { fmt.Printf("%d ", byteval) }; fmt.Println()
	hash := crypto.SHA256
    hashed1 := sha256.Sum256(data)
    fmt.Printf("%x\n",hashed1)
    signature, err := rsa.SignPKCS1v15(rand.Reader, privkey, hash, hashed1[:])

    if err != nil {
      return "", err
	}
    //for _, byteval := range signature { fmt.Printf("%x ", byteval) }; fmt.Println(len(signature))
    signatureB64 := base64.StdEncoding.EncodeToString(signature)
    return signatureB64, nil
}

func HttpRequest1(serverAddress string, priv *rsa.PrivateKey, ecpriv *ecdsa.PrivateKey,
                  did string, url string, use_ec bool, scheme int,
                  object interface{}, httpHeaders map[string]string) ([]byte, error){
    jsonByteArray, _ := json.Marshal(object)
    return HttpRequest(serverAddress, priv, ecpriv, did, url, use_ec, scheme, jsonByteArray, httpHeaders);
}

func HttpRequest(serverAddress string, priv *rsa.PrivateKey, ecpriv *ecdsa.PrivateKey,
                 did string, url string, use_ec bool, scheme int,
                 jsonByteArray []byte, httpHeaders map[string]string) ([]byte, error){
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonByteArray))
    trace := &httptrace.ClientTrace{
        DNSDone: func(dnsInfo httptrace.DNSDoneInfo) {
            fmt.Printf("DNS Info: %+v\n", dnsInfo)
        },
        GotConn: func(connInfo httptrace.GotConnInfo) {
            fmt.Printf("Got Conn: %+v\n", connInfo)
        },
    }

    var urlForSignature = url
    var queryStartIndex = strings.IndexRune(urlForSignature, '?')
    if (queryStartIndex > 0) {
      var query = urlForSignature[queryStartIndex+1:]
      var path = urlForSignature[:queryStartIndex]
      var queryParams = strings.Split(query, "&")
      sort.Strings(queryParams)
      sortedQuery := strings.Join(queryParams, "&")
      urlForSignature = path + "?" + sortedQuery
    }
    var relativeUrl = urlForSignature[len(serverAddress):]
    fmt.Printf("urlForSignature=%s\n", urlForSignature)
    fmt.Printf("relativeUrl=%s\n", relativeUrl)
    var dataToSign string
    /*
    var regex = "/%%/g"
    dataToSign = strings.Replace(relativeUrl, regex, "\\%", 1) +
                     "%" + strings.Replace(GetClientVersionHeader(), regex, "\\%", 1) +
                     "%" + strings.Replace(string(jsonByteArray), regex, "\\%", 1);
                     */
   if (scheme == 1) {
     dataToSign = relativeUrl + string(jsonByteArray)
   }
   if (scheme == 2) {
     dataToSign = relativeUrl + "%%" + GetClientVersionHeader() + "%%" + string(jsonByteArray)
   }
    if (use_ec) {
      fmt.Printf("dataToSign=%s\n",dataToSign)
      signatureB64, _ := EcdsaSign([]byte(dataToSign), ecpriv)
      httpHeaders["Content-Signature"] = fmt.Sprintf("data:%s;key-id:%s;scheme:%1d", signatureB64, did, scheme)
    } else {
      fmt.Printf("dataToSign=%s\n",dataToSign)
      signatureB64, _ := RsaSign([]byte(dataToSign), priv)
      httpHeaders["Content-Signature"] = fmt.Sprintf("data:%s;key-id:%s;scheme:%1d", signatureB64, did, scheme)
    }

    req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
    for header, value := range httpHeaders {
      req.Header.Set(header, value)
    }
    dump, err := httputil.DumpRequestOut(req, true)
    fmt.Printf("================= Request Dump ==================================================\n");
    fmt.Printf("%s\n",dump)
    fmt.Printf("================= End of Reqeust Dump==================================================\n");
    client := &http.Client{}
    resp, err := client.Do(req)
    CheckError(err)

    dump, err = httputil.DumpResponse(resp, true)
    fmt.Printf("================= Response Dump ==================================================\n");
    fmt.Printf("%s\n",dump)
    fmt.Printf("================= End of Response Dump==================================================\n");
    defer resp.Body.Close()
    return ioutil.ReadAll(resp.Body)
}

