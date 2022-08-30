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

type CallDetail struct {
	RequestInfo RequestInfo
	RespInfo    RespInfo
}

type RequestInfo struct {
	Method string
	Url    string
	Body   string
	Header http.Header
}

type RespInfo struct {
	Header http.Header
	Body   string
}

func (c Client) GetAccountInfo() (CallDetail, RespOrgInfo, error) {
	var result RespOrgInfo

	callDetail, body, err := c.Request("GET", "/v1/custody/org_info/", map[string]string{})
	if err != nil {
		return callDetail, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return callDetail, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	return callDetail, result, nil
}

func (c Client) GetCoinInfo(coin string) (CallDetail, RespCoinInfo, error) {
	var result RespCoinInfo

	callDetail, body, err := c.Request("GET", "/v1/custody/coin_info/", map[string]string{
		"coin": coin,
	})
	if err != nil {
		return callDetail, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return callDetail, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	return callDetail, result, nil
}

func (c Client) NewDepositAddress(coin string, nativeSegwit bool) (CallDetail, RespNewAddress, error) {
	var result RespNewAddress
	var params = map[string]string{
		"coin": coin,
	}
	if nativeSegwit {
		params["native_segwit"] = "true"
	}

	callDetail, body, err := c.Request("POST", "/v1/custody/new_address/", params)
	if err != nil {
		return callDetail, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return callDetail, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	return callDetail, result, nil
}

func (c Client) BatchNewDepositAddress(coin string, count int, nativeSegwit bool) (CallDetail, RespNewAddresses, error) {
	var result RespNewAddresses
	var params = map[string]string{
		"coin":  coin,
		"count": strconv.Itoa(count),
	}
	if nativeSegwit {
		params["native_segwit"] = "true"
	}

	callDetail, body, err := c.Request("POST", "/v1/custody/new_addresses/", params)
	if err != nil {
		return callDetail, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return callDetail, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	return callDetail, result, nil
}

func (c Client) VerifyDepositAddress(coin string, address string) (CallDetail, RespNewAddresses, error) {
	var result RespNewAddresses
	var params = map[string]string{
		"coin":    coin,
		"address": address,
	}

	callDetail, body, err := c.Request("GET", "/v1/custody/address_info/", params)
	if err != nil {
		return callDetail, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return callDetail, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	return callDetail, result, nil
}

func (c Client) BatchVerifyDepositAddress(coin string, addresses []string) (CallDetail, RespNewAddresses, error) {
	var result RespNewAddresses
	var params = map[string]string{
		"coin":    coin,
		"address": strings.Join(addresses, ","),
	}

	callDetail, body, err := c.Request("GET", "/v1/custody/addresses_info/", params)
	if err != nil {
		return callDetail, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return callDetail, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	if len(result.Result.Addresses) > 0 {
		result.Result.Addresses = strings.Split(result.Result.Addresses[0], ",")
	}

	return callDetail, result, nil
}

func (c Client) VerifyValidAddress(coin string, addresses string) (CallDetail, RespIsValidAddress, error) {
	var result RespIsValidAddress
	var params = map[string]string{
		"coin":    coin,
		"address": addresses,
	}

	callDetail, body, err := c.Request("GET", "/v1/custody/is_valid_address/", params)
	if err != nil {
		return callDetail, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return callDetail, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	return callDetail, result, nil
}

func (c Client) GetAddressHistory(coin string) (CallDetail, RespAddressHistory, error) {
	var result RespAddressHistory
	var params = map[string]string{
		"coin": coin,
	}

	callDetail, body, err := c.Request("GET", "/v1/custody/address_history/", params)
	if err != nil {
		return callDetail, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return callDetail, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	return callDetail, result, nil
}

func (c Client) GetAddressHistoryWithPage(params map[string]string) (CallDetail, RespAddressHistory, error) {
	var result RespAddressHistory

	callDetail, body, err := c.Request("GET", "/v1/custody/address_history/", params)
	if err != nil {
		return callDetail, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return callDetail, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	return callDetail, result, nil
}

func (c Client) GetTransactionDetails(txId string) (CallDetail, RespTransaction, error) {
	var result RespTransaction
	var params = map[string]string{
		"id": txId,
	}

	callDetail, body, err := c.Request("GET", "/v1/custody/transaction/", params)
	if err != nil {
		return callDetail, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return callDetail, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	return callDetail, result, nil
}

func (c Client) GetTransactionsById(params map[string]string) (CallDetail, RespTransactions, error) {
	var result RespTransactions

	callDetail, body, err := c.Request("GET", "/v1/custody/transactions_by_id/", params)
	if err != nil {
		return callDetail, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return callDetail, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	return callDetail, result, nil
}

func (c Client) GetTransactionsByTxid(txid string) (CallDetail, RespTransaction, error) {
	var result RespTransaction
	var params = map[string]string{
		"txid": txid,
	}

	callDetail, body, err := c.Request("GET", "/v1/custody/transaction_by_txid/", params)
	if err != nil {
		return callDetail, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return callDetail, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	return callDetail, result, nil

}

func (c Client) GetTransactionsByTime(params map[string]string) (CallDetail, RespTransactions, error) {
	var result RespTransactions

	callDetail, body, err := c.Request("GET", "/v1/custody/transactions_by_time/", params)
	if err != nil {
		return callDetail, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return callDetail, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	return callDetail, result, nil

}

func (c Client) GetPendingTransactions(params map[string]string) (CallDetail, RespTransactions, error) {
	var result RespTransactions

	callDetail, body, err := c.Request("GET", "/v1/custody/pending_transactions/", params)
	if err != nil {
		return callDetail, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return callDetail, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	return callDetail, result, nil

}

func (c Client) GetPendingTransaction(id string) (CallDetail, RespTransactions, error) {
	var result RespTransactions

	callDetail, body, err := c.Request("GET", "/v1/custody/pending_transactions/", map[string]string{
		"id": id,
	})
	if err != nil {
		return callDetail, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return callDetail, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	return callDetail, result, nil

}

func (c Client) GetTransactionHistory(params map[string]string) (CallDetail, RespTransactions, error) {
	var result RespTransactions

	callDetail, body, err := c.Request("GET", "/v1/custody/transaction_history/", params)
	if err != nil {
		return callDetail, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return callDetail, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	return callDetail, result, nil

}

func (c Client) QueryWithdrawInfo(requestId string) (CallDetail, RespTransaction, error) {
	var result RespTransaction

	callDetail, body, err := c.Request("GET", "/v1/custody/withdraw_info_by_request_id/", map[string]string{"request_id": requestId})
	if err != nil {
		return callDetail, result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return callDetail, result, fmt.Errorf("error when unmarshal resp body: %v, err: %v", string(body), err.Error())
	}

	return callDetail, result, nil

}

func (c Client) Request(method string, path string, params map[string]string) (callDetail CallDetail, body []byte, err error) {
	httpClient := &http.Client{}
	nonce := fmt.Sprintf("%d", time.Now().Unix()*1000)
	sorted := SortParams(params)
	var req *http.Request
	reqInfo := RequestInfo{
		Method: method,
	}

	if method == "POST" {
		req, err = http.NewRequest(method, c.Env.Host+path, strings.NewReader(sorted))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		reqInfo.Url = c.Env.Host + path
		reqInfo.Body = sorted
	} else {
		req, err = http.NewRequest(method, c.Env.Host+path+"?"+sorted, strings.NewReader(""))
		reqInfo.Url = c.Env.Host + path + "?" + sorted
	}
	if err != nil {
		return callDetail, nil, fmt.Errorf("error when new request, method: %v, url: %v, err: %v", method, c.Env.Host+path, err.Error())
	}

	content := strings.Join([]string{method, path, nonce, sorted}, "|")

	req.Header.Set("Biz-Api-Key", c.Signer.GetPublicKey())
	req.Header.Set("Biz-Api-Nonce", nonce)
	req.Header.Set("Biz-Api-Signature", c.Signer.Sign(content))
	reqInfo.Header = req.Header

	if c.Debug {
		fmt.Println("request >>>>>>>>")
		fmt.Println(method, "\n", path, "\n", params, "\n", content, "\n", req.Header)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return callDetail, nil, fmt.Errorf("error when send request, method: %v, url: %v, err: %v", method, c.Env.Host+path, err.Error())
	}
	defer resp.Body.Close()

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return callDetail, nil, fmt.Errorf("error when read response body data, method: %v, url: %v, err: %v", method, c.Env.Host+path, err.Error())
	}

	timestamp := resp.Header.Get("Biz-Timestamp")
	signature := resp.Header.Get("Biz-Resp-Signature")
	if c.Debug {
		fmt.Println("response <<<<<<<<")
		fmt.Println(string(body), "\n", timestamp, "\n", signature)
	}
	success := c.VerifyEcc(string(body)+"|"+timestamp, signature)
	if !success {
		return callDetail, nil, fmt.Errorf("response signature verify failed")
	}

	callDetail.RequestInfo = reqInfo
	callDetail.RespInfo = RespInfo{
		Header: resp.Header,
		Body:   string(body),
	}

	return callDetail, body, nil
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
