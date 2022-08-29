package cobo_custody

import (
	"github.com/shopspring/decimal"
	"time"
)

type RespOrgInfo struct {
	ApiError ApiError
	Success  bool    `json:"success"`
	Result   OrgInfo `json:"result"`
}

type RespSupportedCoins struct {
	ApiError ApiError
	Success  bool   `json:"success"`
	Result   []Coin `json:"result"`
}

type RespCoinInfo struct {
	ApiError ApiError
	Success  bool     `json:"success"`
	Result   CoinInfo `json:"result"`
}

type RespNewAddress struct {
	ApiError ApiError
	Success  bool        `json:"success"`
	Result   AddressInfo `json:"result"`
}

type RespNewAddresses struct {
	ApiError ApiError
	Success  bool          `json:"success"`
	Result   AddressesInfo `json:"result"`
}

type RespAddressInfo struct {
	ApiError ApiError
	Success  bool        `json:"success"`
	Result   AddressInfo `json:"result"`
}

type RespAddressesInfo struct {
	ApiError ApiError
	Success  bool          `json:"success"`
	Result   AddressesInfo `json:"result"`
}

type RespIsValidAddress struct {
	ApiError ApiError
	Success  bool `json:"success"`
	Result   bool `json:"result"`
}

type RespAddressHistory struct {
	ApiError ApiError
	Success  bool          `json:"success"`
	Result   []AddressInfo `json:"result"`
}

type RespTransaction struct {
	ApiError ApiError
	Success  bool        `json:"success"`
	Result   Transaction `json:"result"`
}

type RespTransactions struct {
	ApiError ApiError
	Success  bool          `json:"success"`
	Result   []Transaction `json:"result"`
}

type OrgInfo struct {
	Name   string  `json:"name"`
	Assets []Asset `json:"assets"`
}

type Asset struct {
	Coin                string          `json:"coin"`
	DisplayCode         string          `json:"display_code"`
	Description         string          `json:"description"`
	Decimal             int             `json:"decimal"`
	CanDeposit          bool            `json:"can_deposit"`
	CanWithdraw         bool            `json:"can_withdraw"`
	Balance             decimal.Decimal `json:"balance"`
	AbsBalance          decimal.Decimal `json:"abs_balance"`
	FeeCoin             string          `json:"fee_coin"`
	AbsEstimateFee      decimal.Decimal `json:"abs_estimate_fee"`
	ConfirmingThreshold int             `json:"confirming_threshold"`
	DustThreshold       int             `json:"dust_threshold"`
	TokenAddress        string          `json:"token_address"`
	RequireMemo         bool            `json:"require_memo"`
}

type Coin struct {
	Coin        string `json:"coin"`
	DisplayCode string `json:"display_code"`
	Description string `json:"description"`
	Decimal     int    `json:"decimal"`
	CanDeposit  bool   `json:"can_deposit"`
	CanWithdraw bool   `json:"can_withdraw"`
	RequireMemo bool   `json:"require_memo"`
}

type CoinInfo struct {
	Coin                string `json:"coin"`
	DisplayCode         string `json:"display_code"`
	Description         string `json:"description"`
	Decimal             int    `json:"decimal"`
	CanDeposit          bool   `json:"can_deposit"`
	CanWithdraw         bool   `json:"can_withdraw"`
	RequireMemo         bool   `json:"require_memo"`
	Balance             string `json:"balance"`
	AbsBalance          string `json:"abs_balance"`
	FeeCoin             string `json:"fee_coin"`
	AbsEstimateFee      string `json:"abs_estimate_fee"`
	ConfirmingThreshold int    `json:"confirming_threshold"`
	DustThreshold       int    `json:"dust_threshold"`
	TokenAddress        string `json:"token_address"`
}

type AddressInfo struct {
	Coin    string `json:"coin"`
	Address string `json:"address"`
}

type AddressesInfo struct {
	Coin      string   `json:"coin"`
	Addresses []string `json:"addresses"`
}

type Transaction struct {
	ID                  string          `json:"id"`
	Coin                string          `json:"coin"`
	DisplayCode         string          `json:"display_code"`
	Description         string          `json:"description"`
	Decimal             int             `json:"decimal"`
	Address             string          `json:"address"`
	SourceAddress       string          `json:"source_address"`
	Side                string          `json:"side"`
	Amount              decimal.Decimal `json:"amount"`
	AbsAmount           decimal.Decimal `json:"abs_amount"`
	Txid                string          `json:"txid"`
	VoutN               int             `json:"vout_n"`
	RequestID           string          `json:"request_id"`
	Status              string          `json:"status"`
	AbsCoboFee          decimal.Decimal `json:"abs_cobo_fee"`
	CreatedTimestamp    int64           `json:"created_time"`
	CreatedTime         time.Time       `json:"-"`
	LastTimestamp       int64           `json:"last_time"`
	LastTime            time.Time       `json:"-"`
	ConfirmedNum        int             `json:"confirmed_num"`
	TxDetail            TxDetail        `json:"tx_detail"`
	SourceAddressDetail string          `json:"source_address_detail"`
	Memo                string          `json:"memo"`
	ConfirmingThreshold int             `json:"confirming_threshold"`
	FeeCoin             string          `json:"fee_coin"`
	FeeAmount           int             `json:"fee_amount"`
	FeeDecimal          int             `json:"fee_decimal"`
	Fee                 decimal.Decimal `json:"-"`
	Type                string          `json:"type"`
}

type TxDetail struct {
	Txid      string `json:"txid"`
	Blocknum  int    `json:"blocknum"`
	Blockhash string `json:"blockhash"`
	Fee       int    `json:"fee"`
	Actualgas int    `json:"actualgas"`
	Gasprice  int    `json:"gasprice"`
	Hexstr    string `json:"hexstr"`
}
