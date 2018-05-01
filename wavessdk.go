package wavesdktest

import (
  "fmt"
	"github.com/mr-tron/base58/base58"
  "golang.org/x/crypto/blake2b"
  "crypto/sha256"
  "github.com/miguelsandro/curve25519-go/axlsign"
  "github.com/ethereum/go-ethereum/crypto/sha3"
  "encoding/json"
	"time"
  "crypto/rand"
	"encoding/binary"
	"bytes"
	"io/ioutil"
	"net/http"
)

type Address struct {
    Address string
    PublicKey string
    PrivateKey string
    Callbacks map[string]func(Address)
}

type Asset struct {
    AssetId string
}

func GenAddress(seed string) Address {
      //encoded := base58.Encode([]byte(seed))
      //fmt.Println(string(encoded))
      encodedNonce := append([]byte("\x00\x00\x00\x00"), seed...)
      //fmt.Printf("%q\n", encodedNonce)

      black := blake2b.Sum256(encodedNonce)
      //fmt.Printf("%q\n", black[:])

      hash := sha3.NewKeccak256()
      hash.Write(black[:])
      var buf []byte
      seedHash := hash.Sum(buf)
      //fmt.Printf("%q\n", seedHash[:])

      accountSeedHash := sha256.Sum256(seedHash[:])
      //fmt.Printf("%q\n", accountSeedHash[:])

      keyPair := axlsign.GenerateKeyPair(accountSeedHash[:])
      //fmt.Printf("%q\n", base58.Encode(keyPair.PrivateKey))
      //fmt.Printf("%q\n", base58.Encode(keyPair.PublicKey))

      black2 := blake2b.Sum256(keyPair.PublicKey)
      hash = sha3.NewKeccak256()
      hash.Write(black2[:])
      seedHash2 := hash.Sum(buf)

      unhashedAddress := append([]byte("\x01W"), seedHash2[0:20]...)

      black3 := blake2b.Sum256(unhashedAddress)
      hash = sha3.NewKeccak256()
      hash.Write(black3[:])
      addressHash := hash.Sum(buf)

      addr := base58.Encode(append(unhashedAddress, addressHash[0:4]...))
      //fmt.Println(addr)
      res := Newaddress()
      res.Address = addr
      res.PublicKey = base58.Encode(keyPair.PublicKey)
      res.PrivateKey = base58.Encode(keyPair.PrivateKey)
      return res
}

type transaction struct {
    SenderPublicKeyDec string `json:"senderPublicKey"`
    RecAddress string `json:"recipient"`
    Amount int64 `json:"amount"`
    AssetId string `json:"assetId"`
    TxFee int64 `json:"fee"`
    Timestamp int64 `json:"timestamp"`
    Attachment string `json:"attachment"`
    Signature string `json:"signature"`
}
func Newaddress() Address {
    var a Address
    a.Callbacks = make(map[string]func(Address))
    return a
}

func (addr *Address) On(calltype string, callback func(Address)) {
    addr.Callbacks[calltype] = callback
}

func (addr *Address) callback(calltype string) {
    for k, v := range addr.Callbacks {
        if k == calltype{
          v(*addr)
        }
    }
}

func (addr *Address) Transfer(anotherAddress string, amount int64, fee int64) {

    timestamp := time.Now().Unix() * 1000

    byteBuffer := make([]byte, 8)
    publicKey, _ := base58.Decode(addr.PublicKey)
    data := append([]byte("\x04"), publicKey...)
    data = append(data, []byte("\x00\x00")...)
    binary.BigEndian.PutUint64(byteBuffer, uint64(timestamp))
    data = append(data, byteBuffer...)
    binary.BigEndian.PutUint64(byteBuffer, uint64(amount))
    data = append(data, byteBuffer...)
    binary.BigEndian.PutUint64(byteBuffer, uint64(fee))
    data = append(data, byteBuffer...)
    recipient, _ := base58.Decode(anotherAddress)
    data = append(data, []byte(recipient)...)
    data = append(data, []byte("\x00\x00")...)

    //fmt.Printf("%q\n", data[:])
    random := make([]byte, 64)
    rand.Read(random)
    privateKey, _ := base58.Decode(addr.PrivateKey)
    signature := axlsign.Sign(privateKey, data, random)

    trans := &transaction{
      SenderPublicKeyDec:   addr.PublicKey,
      RecAddress: anotherAddress,
      Amount: amount,
      TxFee: fee,
      Timestamp: timestamp,
      Attachment: "",
      Signature: base58.Encode(signature),
    }
    transJson, _ := json.Marshal(trans)

    //fmt.Println(string(transJson))
    post(transJson)
    addr.callback("transaction")
}

func (addr *Address) TransferAsset(anotherAddress string, amount int64, fee int64, as *Asset) {

    timestamp := time.Now().Unix() * 1000

    byteBuffer := make([]byte, 8)
    publicKey, _ := base58.Decode(addr.PublicKey)
    data := append([]byte("\x04"), publicKey...)
    assetId, _ := base58.Decode(as.AssetId)
    data = append(data, []byte("\x01")...)
    data = append(data, assetId...)
    data = append(data, []byte("\x00")...)
    binary.BigEndian.PutUint64(byteBuffer, uint64(timestamp))
    data = append(data, byteBuffer...)
    binary.BigEndian.PutUint64(byteBuffer, uint64(amount))
    data = append(data, byteBuffer...)
    binary.BigEndian.PutUint64(byteBuffer, uint64(fee))
    data = append(data, byteBuffer...)
    recipient, _ := base58.Decode(anotherAddress)
    data = append(data, []byte(recipient)...)
    data = append(data, []byte("\x00\x00")...)

    //fmt.Printf("%q\n", data[:])
    random := make([]byte, 64)
    rand.Read(random)
    privateKey, _ := base58.Decode(addr.PrivateKey)
    signature := axlsign.Sign(privateKey, data, random)

    trans := &transaction{
      SenderPublicKeyDec:   addr.PublicKey,
      RecAddress: anotherAddress,
      Amount: amount,
      AssetId: as.AssetId,
      TxFee: fee,
      Timestamp: timestamp,
      Attachment: "",
      Signature: base58.Encode(signature),
    }
    transJson, _ := json.Marshal(trans)

    //fmt.Println(string(transJson))
    post(transJson)
    addr.callback("transaction")
}


func post(json []byte) {
    url := "https://nodes.wavesnodes.com/assets/broadcast/transfer"

    req, err := http.NewRequest("POST", url, bytes.NewBuffer(json))
    req.Header.Set("Content-Type", "application/json")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
      panic(err)
    }
    defer resp.Body.Close()

    //fmt.Println("response Status:", resp.Status)
    //fmt.Println("response Headers:", resp.Header)
    body, err := ioutil.ReadAll(resp.Body)
    fmt.Println("response Body:", string(body))
    if err != nil {
      fmt.Println(err)
    }
}
