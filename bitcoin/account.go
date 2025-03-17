package bitcoin

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/log"
	"github.com/pkg/errors"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

type FormatAddress struct {
	P2pkhAddress  string
	P2wpkhAddress string
	P2shAddress   string
	P2trAddress   string
}

func ExtractAddressesFromVinScriptSigHex(scriptSigHex string) (string, error) {
	scriptSigBytes, err := hex.DecodeString(scriptSigHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode scriptSig hex: %v", err)
	}
	disasmString, err := txscript.DisasmString(scriptSigBytes)
	if err != nil {
		return "", fmt.Errorf("failed to disassemble scriptSig: %v", err)
	}
	tokens := strings.Split(disasmString, " ")
	if len(tokens) < 2 {
		return "", fmt.Errorf("invalid P2PKH scriptSig format")
	}
	pubKeyHex := tokens[len(tokens)-1]

	allAddress, err := publicKeyToAddress(pubKeyHex)
	if err != nil {
		return "", err
	}
	return allAddress.P2pkhAddress + "|" + allAddress.P2wpkhAddress + "|" + allAddress.P2shAddress + allAddress.P2trAddress, nil
}

func ExtractMultiAddress(witness string) (string, error) {
	var allAddress string
	redeemScriptBytes, err := hex.DecodeString(witness)
	_, addressList, _, _ := txscript.ExtractPkScriptAddrs(redeemScriptBytes, &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("failed to parse P2WSH redeemScript: %v", err)
	}
	for _, address := range addressList {
		allAddress += address.EncodeAddress() + "|"
	}
	return allAddress, nil
}

func ExtractNonMultiAddress(witness string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(witness)
	pubKey, err := btcec.ParsePubKey(pubKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse P2WPKH pubKey: %v", err)
	}
	pubKeyHex := hex.EncodeToString(pubKey.SerializeCompressed())
	allAddress, err := publicKeyToAddress(pubKeyHex)
	if err != nil {
		return "", err
	}
	return allAddress.P2pkhAddress + "|" + allAddress.P2wpkhAddress + "|" + allAddress.P2shAddress + allAddress.P2trAddress, nil
}

func publicKeyToAddress(publicKey string) (*FormatAddress, error) {
	pubKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil || (len(pubKeyBytes) != 33 && len(pubKeyBytes) != 65) {
		return nil, errors.New("invalid public key format")
	}
	pubKeyHash := btcutil.Hash160(pubKeyBytes)
	p2pkhAddr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	if err != nil {
		log.Warn("create p2pkh address fail", "err", err)
	}
	p2wpkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	if err != nil {
		log.Warn("create p2wpkh fail", "err", err)
	}
	witnessPubKeyHash, _ := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	script, err := txscript.PayToAddrScript(witnessPubKeyHash)
	if err != nil {
		log.Warn("parse p2sh address script fail", "err", err)
	}
	p2shAddr, err := btcutil.NewAddressScriptHash(script, &chaincfg.MainNetParams)
	if err != nil {
		log.Warn("create p2sh address fail", "err", err)
	}
	pubKey, err := btcec.ParsePubKey(pubKeyHash)
	if err != nil {
		log.Warn("parse public key fail", "err", err)
	}
	taprootPubKey := schnorr.SerializePubKey(pubKey)
	taprootAddr, err := btcutil.NewAddressTaproot(taprootPubKey, &chaincfg.MainNetParams)
	if err != nil {
		log.Warn("create taproot address fail", "err", err)
	}
	return &FormatAddress{
		P2pkhAddress:  p2pkhAddr.EncodeAddress(),
		P2wpkhAddress: p2wpkhAddr.EncodeAddress(),
		P2shAddress:   p2shAddr.EncodeAddress(),
		P2trAddress:   taprootAddr.EncodeAddress(),
	}, nil
}
