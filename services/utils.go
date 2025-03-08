package grpc

import (
	"math"
	"math/big"
	"strconv"

	"github.com/shopspring/decimal"

	"github.com/dapplink-labs/wallet-chain-btc/proto/btc"
)

const (
	btcDecimals = 8
)

type DecodeTxRes struct {
	Hash       string
	SignHashes [][]byte
	Vins       []*btc.Vin
	Vouts      []*btc.Vout
	CostFee    *big.Int
}

func btcToSatoshi(btcCount float64) *big.Int {
	amount := strconv.FormatFloat(btcCount, 'f', -1, 64)
	amountDm, _ := decimal.NewFromString(amount)
	tenDm := decimal.NewFromFloat(math.Pow(10, float64(btcDecimals)))
	satoshiDm, _ := big.NewInt(0).SetString(amountDm.Mul(tenDm).String(), 10)
	return satoshiDm
}
