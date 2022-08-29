package cobo_custody

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec"
)

type Client struct {
	Signer ApiSigner
	Env    Env
	Debug  bool
}

func (c Client) GetAccountInfo() (http.Header, RespOrgInfo, error) {
	var result RespOrgInfo

	header, body, err := c.Request("GET", "/v1/custody/org_info/", map[string]string{})
	if err != nil {
		return nil, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	return header, result, nil
}

func (c Client) GetCoinInfo(coin string) (http.Header, RespCoinInfo, error) {
	var result RespCoinInfo

	header, body, err := c.Request("GET", "/v1/custody/coin_info/", map[string]string{
		"coin": coin,
	})
	if err != nil {
		return nil, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	return header, result, nil
}

func (c Client) NewDepositAddress(coin string, nativeSegwit bool) (http.Header, RespNewAddress, error) {
	var result RespNewAddress
	var params = map[string]string{
		"coin": coin,
	}
	if nativeSegwit {
		params["native_segwit"] = "true"
	}

	header, body, err := c.Request("POST", "/v1/custody/new_address/", params)
	if err != nil {
		return nil, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	return header, result, nil
}

func (c Client) BatchNewDepositAddress(coin string, count int, nativeSegwit bool) (http.Header, RespNewAddresses, error) {
	var result RespNewAddresses
	var params = map[string]string{
		"coin":  coin,
		"count": strconv.Itoa(count),
	}
	if nativeSegwit {
		params["native_segwit"] = "true"
	}

	header, body, err := c.Request("POST", "/v1/custody/new_addresses/", params)
	if err != nil {
		return nil, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	return header, result, nil
}

func (c Client) VerifyDepositAddress(coin string, address string) (http.Header, RespNewAddresses, error) {
	var result RespNewAddresses
	var params = map[string]string{
		"coin":    coin,
		"address": address,
	}

	header, body, err := c.Request("GET", "/v1/custody/address_info/", params)
	if err != nil {
		return nil, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	return header, result, nil
}

func (c Client) BatchVerifyDepositAddress(coin string, addresses []string) (http.Header, RespNewAddresses, error) {
	var result RespNewAddresses
	var params = map[string]string{
		"coin":    coin,
		"address": strings.Join(addresses, ","),
	}

	header, body, err := c.Request("GET", "/v1/custody/addresses_info/", params)
	if err != nil {
		return nil, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	if len(result.Result.Addresses) > 0 {
		result.Result.Addresses = strings.Split(result.Result.Addresses[0], ",")
	}

	return header, result, nil
}

func (c Client) VerifyValidAddress(coin string, addresses string) (http.Header, RespIsValidAddress, error) {
	var result RespIsValidAddress
	var params = map[string]string{
		"coin":    coin,
		"address": addresses,
	}

	header, body, err := c.Request("GET", "/v1/custody/is_valid_address/", params)
	if err != nil {
		return nil, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	return header, result, nil
}

func (c Client) GetAddressHistory(coin string) (http.Header, RespAddressHistory, error) {
	var result RespAddressHistory
	var params = map[string]string{
		"coin": coin,
	}

	header, body, err := c.Request("GET", "/v1/custody/address_history/", params)
	if err != nil {
		return nil, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	return header, result, nil
}

func (c Client) GetAddressHistoryWithPage(params map[string]string) (http.Header, RespAddressHistory, error) {
	var result RespAddressHistory

	header, body, err := c.Request("GET", "/v1/custody/address_history/", params)
	if err != nil {
		return nil, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	return header, result, nil
}

func (c Client) GetTransactionDetails(txId string) (http.Header, RespTransaction, error) {
	var result RespTransaction
	var params = map[string]string{
		"id": txId,
	}

	header, body, err := c.Request("GET", "/v1/custody/transaction/", params)
	if err != nil {
		return nil, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	return header, result, nil
}

func (c Client) GetTransactionsById(params map[string]string) (http.Header, RespTransaction, error) {
	var result RespTransaction

	header, body, err := c.Request("GET", "/v1/custody/transactions_by_id/", params)
	if err != nil {
		return nil, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	return header, result, nil
}

func (c Client) GetTransactionsByTxid(txid string) (http.Header, RespTransaction, error) {
	var result RespTransaction
	var params = map[string]string{
		"txid": txid,
	}

	header, body, err := c.Request("GET", "/v1/custody/transaction_by_txid/", params)
	if err != nil {
		return nil, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	return header, result, nil

}

func (c Client) GetTransactionsByTime(params map[string]string) (http.Header, RespTransactions, error) {
	var result RespTransactions

	header, body, err := c.Request("GET", "/v1/custody/transactions_by_time/", params)
	if err != nil {
		return nil, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	return header, result, nil

}

func (c Client) GetPendingTransactions(params map[string]string) (http.Header, RespTransactions, error) {
	var result RespTransactions

	header, body, err := c.Request("GET", "/v1/custody/pending_transactions/", params)
	if err != nil {
		return nil, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	return header, result, nil

}

func (c Client) GetPendingTransaction(id string) (http.Header, RespTransactions, error) {
	var result RespTransactions

	header, body, err := c.Request("GET", "/v1/custody/pending_transactions/", map[string]string{
		"id": id,
	})
	if err != nil {
		return nil, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	return header, result, nil

}

func (c Client) GetTransactionHistory(params map[string]string) (http.Header, RespTransactions, error) {
	var result RespTransactions

	header, body, err := c.Request("GET", "/v1/custody/transaction_history/", params)
	if err != nil {
		return nil, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	return header, result, nil

}

func (c Client) QueryWithdrawInfo(requestId string) (http.Header, RespTransaction, error) {
	var result RespTransaction

	header, body, err := c.Request("GET", "/v1/custody/withdraw_info_by_request_id/", map[string]string{"request_id": requestId})
	if err != nil {
		return nil, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	return header, result, nil

}

func (c Client) Request(method string, path string, params map[string]string) (header http.Header, body []byte, err error) {
	httpClient := &http.Client{}
	nonce := fmt.Sprintf("%d", time.Now().Unix()*1000)
	sorted := SortParams(params)
	var req *http.Request
	if method == "POST" {
		req, err = http.NewRequest(method, c.Env.Host+path, strings.NewReader(sorted))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req, err = http.NewRequest(method, c.Env.Host+path+"?"+sorted, strings.NewReader(""))
	}
	if err != nil {
		return nil, nil, fmt.Errorf("error when new request, method: %v, url: %v, err: %v", method, c.Env.Host+path, err.Error())
	}

	content := strings.Join([]string{method, path, nonce, sorted}, "|")

	req.Header.Set("Biz-Api-Key", c.Signer.GetPublicKey())
	req.Header.Set("Biz-Api-Nonce", nonce)
	req.Header.Set("Biz-Api-Signature", c.Signer.Sign(content))

	if c.Debug {
		fmt.Println("request >>>>>>>>")
		fmt.Println(method, "\n", path, "\n", params, "\n", content, "\n", req.Header)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error when send request, method: %v, url: %v, err: %v", method, c.Env.Host+path, err.Error())
	}
	defer resp.Body.Close()

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("error when read response body data, method: %v, url: %v, err: %v", method, c.Env.Host+path, err.Error())
	}

	timestamp := resp.Header.Get("Biz-Timestamp")
	signature := resp.Header.Get("Biz-Resp-Signature")
	if c.Debug {
		fmt.Println("response <<<<<<<<")
		fmt.Println(string(body), "\n", timestamp, "\n", signature)
	}
	success := c.VerifyEcc(string(body)+"|"+timestamp, signature)
	if !success {
		return nil, nil, fmt.Errorf("response signature verify failed")
	}

	return resp.Header, body, nil
}

func SortParams(params map[string]string) string {
	keys := make([]string, len(params))
	i := 0
	for k := range params {
		keys[i] = k
		i++
	}
	sort.Strings(keys)
	sorted := make([]string, len(params))
	i = 0
	for _, k := range keys {
		sorted[i] = k + "=" + url.QueryEscape(params[k])
		i++
	}
	return strings.Join(sorted, "&")
}

func (c Client) VerifyEcc(message string, signature string) bool {
	pubKeyBytes, _ := hex.DecodeString(c.Env.CoboPub)
	pubKey, _ := btcec.ParsePubKey(pubKeyBytes, btcec.S256())

	sigBytes, _ := hex.DecodeString(signature)
	sigObj, _ := btcec.ParseSignature(sigBytes, btcec.S256())

	verified := sigObj.Verify([]byte(Hash256x2(message)), pubKey)
	return verified
}
