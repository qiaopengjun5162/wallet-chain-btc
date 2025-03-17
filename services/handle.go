package services

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/dapplink-labs/wallet-chain-btc/bitcoin"
	"math/big"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/log"
	"github.com/pkg/errors"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"github.com/dapplink-labs/wallet-chain-btc/bitcoin/types"
	"github.com/dapplink-labs/wallet-chain-btc/proto/btc"
)

const BtcDecimal = 10e7

func (wbs *WalletBtcService) ConvertAddress(ctx context.Context, req *btc.ConvertAddressRequest) (*btc.ConvertAddressResponse, error) {
	var address string
	compressedPubKeyBytes, _ := hex.DecodeString(req.PublicKey)
	pubKeyHash := btcutil.Hash160(compressedPubKeyBytes)
	switch req.Format {
	case "p2pkh":
		p2pkhAddr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
		if err != nil {
			log.Error("create p2pkh address fail", "err", err)
			return nil, err
		}
		address = p2pkhAddr.EncodeAddress()
		break
	case "p2wpkh":
		witnessAddr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
		if err != nil {
			log.Error("create p2wpkh fail", "err", err)
		}
		address = witnessAddr.EncodeAddress()
		break
	case "p2sh":
		witnessAddr, _ := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
		script, err := txscript.PayToAddrScript(witnessAddr)
		if err != nil {
			log.Error("create p2sh address script fail", "err", err)
			return nil, err
		}
		p2shAddr, err := btcutil.NewAddressScriptHash(script, &chaincfg.MainNetParams)
		if err != nil {
			log.Error("create p2sh address fail", "err", err)
			return nil, err
		}
		address = p2shAddr.EncodeAddress()
		break
	case "p2tr":
		pubKey, err := btcec.ParsePubKey(compressedPubKeyBytes)
		if err != nil {
			log.Error("parse public key fail", "err", err)
			return nil, err
		}
		taprootPubKey := schnorr.SerializePubKey(pubKey)
		taprootAddr, err := btcutil.NewAddressTaproot(taprootPubKey, &chaincfg.MainNetParams)
		if err != nil {
			log.Error("create taproot address fail", "err", err)
			return nil, err
		}
		address = taprootAddr.EncodeAddress()
	default:
		return nil, errors.New("Do not support address type")
	}
	return &btc.ConvertAddressResponse{
		Code:    btc.ReturnCode_SUCCESS,
		Msg:     "create address success",
		Address: address,
	}, nil
}

func (wbs *WalletBtcService) ValidAddress(ctx context.Context, req *btc.ValidAddressRequest) (*btc.ValidAddressResponse, error) {
	address, err := btcutil.DecodeAddress(req.Address, &chaincfg.MainNetParams)
	if err != nil {
		return &btc.ValidAddressResponse{
			Code: btc.ReturnCode_ERROR,
			Msg:  err.Error(),
		}, nil
	}
	if !address.IsForNet(&chaincfg.MainNetParams) {
		return &btc.ValidAddressResponse{
			Code: btc.ReturnCode_ERROR,
			Msg:  "address is not valid for this network",
		}, nil
	}
	return &btc.ValidAddressResponse{
		Code:  btc.ReturnCode_SUCCESS,
		Msg:   "verify address success",
		Valid: true,
	}, nil
}

func (wbs *WalletBtcService) GetAccount(ctx context.Context, req *btc.AccountRequest) (*btc.AccountResponse, error) {
	balance, err := wbs.thirdPartClient.GetAccountBalance(req.Address)
	if err != nil {
		return &btc.AccountResponse{
			Code:    btc.ReturnCode_ERROR,
			Msg:     "get btc balance fail",
			Balance: "0",
		}, err
	}
	return &btc.AccountResponse{
		Code:    btc.ReturnCode_SUCCESS,
		Msg:     "get btc balance success",
		Balance: balance,
	}, nil
}

func (wbs *WalletBtcService) GetUnspentOutputs(ctx context.Context, req *btc.UnspentOutputsRequest) (*btc.UnspentOutputsResponse, error) {
	utxoList, err := wbs.thirdPartClient.GetAccountUtxo(req.Address)
	if err != nil {
		return &btc.UnspentOutputsResponse{
			Code:           btc.ReturnCode_ERROR,
			Msg:            err.Error(),
			UnspentOutputs: nil,
		}, err
	}
	var unspentOutputList []*btc.UnspentOutput
	for _, value := range utxoList {
		unspentOutput := &btc.UnspentOutput{
			TxHashBigEndian: value.TxHashBigEndian,
			TxId:            value.TxHash,
			TxOutputN:       value.TxOutputN,
			Script:          value.Script,
			UnspentAmount:   strconv.FormatUint(value.Value, 10),
			Index:           value.TxIndex,
		}
		unspentOutputList = append(unspentOutputList, unspentOutput)
	}
	return &btc.UnspentOutputsResponse{
		Code:           btc.ReturnCode_SUCCESS,
		Msg:            "get unspent outputs success",
		UnspentOutputs: unspentOutputList,
	}, nil
}

func (wbs *WalletBtcService) GetBlockByNumber(ctx context.Context, req *btc.BlockNumberRequest) (*btc.BlockResponse, error) {
	blockHash, err := wbs.btcClient.Client.GetBlockHash(req.Height)
	if err != nil {
		log.Error("get block hash by number fail", "err", err)
		return &btc.BlockResponse{
			Code: btc.ReturnCode_ERROR,
			Msg:  "get block hash fail",
		}, err
	}
	var params []json.RawMessage
	numBlocksJSON, _ := json.Marshal(blockHash)
	params = []json.RawMessage{numBlocksJSON}
	block, _ := wbs.btcClient.Client.RawRequest("getblock", params)
	var resultBlock types.BlockData
	err = json.Unmarshal(block, &resultBlock)
	if err != nil {
		log.Error("Unmarshal json fail", "err", err)
	}
	var txList []*btc.TransactionList
	for _, txid := range resultBlock.Tx {
		txIdJson, _ := json.Marshal(txid)
		boolJSON, _ := json.Marshal(true)
		dataJSON := []json.RawMessage{txIdJson, boolJSON}
		tx, err := wbs.btcClient.Client.RawRequest("getrawtransaction", dataJSON)
		if err != nil {
			fmt.Println("get raw transaction fail", "err", err)
		}
		var rawTx types.RawTransactionData
		err = json.Unmarshal(tx, &rawTx)
		if err != nil {
			log.Error("json unmarshal fail", "err", err)
			return nil, err
		}
		var vinList []*btc.Vin
		for _, vin := range rawTx.Vin {
			log.Info("Vin script and witness", "vinScriptSigHex", vin.ScriptSig.Hex, "vinTxInWitness", vin.TxInWitness)
			var btcAddress string
			if vin.ScriptSig.Hex == "" && len(vin.TxInWitness) > 0 {
				if len(vin.TxInWitness) >= 2 {
					btcAddress, _ = bitcoin.ExtractMultiAddress(vin.TxInWitness[1])
				} else {
					btcAddress, _ = bitcoin.ExtractNonMultiAddress(vin.TxInWitness[0])
				}
			} else {
				btcAddress, _ = bitcoin.ExtractAddressesFromVinScriptSigHex(vin.ScriptSig.Hex)
			}
			vinItem := &btc.Vin{
				Hash:     vin.TxId,
				Vout:     uint32(vin.Vout),
				Amount:   0,
				Address:  btcAddress,
				Sequence: vin.Sequence,
			}
			vinList = append(vinList, vinItem)
		}
		var voutList []*btc.Vout
		for _, vout := range rawTx.Vout {
			voutAmount := vout.Value * BtcDecimal
			voutItem := &btc.Vout{
				Address: vout.ScriptPubKey.Address,
				Amount:  uint64(voutAmount),
				Index:   uint32(vout.N),
				ScriptPubKey: &btc.ScriptPubKey{
					Asm:     vout.ScriptPubKey.Asm,
					Desc:    vout.ScriptPubKey.Desc,
					Hex:     vout.ScriptPubKey.Hex,
					Address: vout.ScriptPubKey.Address,
					Type:    vout.ScriptPubKey.Type,
				},
			}
			voutList = append(voutList, voutItem)
		}
		txItem := &btc.TransactionList{
			Hash: rawTx.Hash,
			Vin:  vinList,
			Vout: voutList,
		}
		txList = append(txList, txItem)
	}
	return &btc.BlockResponse{
		Code:   btc.ReturnCode_SUCCESS,
		Msg:    "get block by number success",
		Height: uint64(req.Height),
		Hash:   blockHash.String(),
		TxList: txList,
	}, nil
}

func (wbs *WalletBtcService) GetBlockByHash(ctx context.Context, req *btc.BlockHashRequest) (*btc.BlockResponse, error) {
	var params []json.RawMessage
	numBlocksJSON, _ := json.Marshal(req.Hash)
	params = []json.RawMessage{numBlocksJSON}
	block, _ := wbs.btcClient.Client.RawRequest("getblock", params)

	log.Info("get block success", "block", block)

	var resultBlock types.BlockData

	err := json.Unmarshal(block, &resultBlock)
	if err != nil {
		log.Error("Unmarshal json fail", "err", err)
	}

	log.Info("parse block success", "resultBlock", resultBlock)

	var txList []*btc.TransactionList
	for _, txid := range resultBlock.Tx {
		txIdJson, _ := json.Marshal(txid)
		boolJSON, _ := json.Marshal(true)
		dataJSON := []json.RawMessage{txIdJson, boolJSON}
		tx, err := wbs.btcClient.Client.RawRequest("getrawtransaction", dataJSON)
		if err != nil {
			fmt.Println("get raw transaction fail", "err", err)
		}
		var rawTx types.RawTransactionData
		err = json.Unmarshal(tx, &rawTx)
		if err != nil {
			log.Error("json unmarshal fail", "err", err)
			return nil, err
		}
		var vinList []*btc.Vin
		for _, vin := range rawTx.Vin {
			if vin.TxId == "" { // coinbase tx
				continue
			}
			log.Info("Vin script and witness", "vinScriptSigHex", vin.ScriptSig.Hex, "vinTxInWitness", vin.TxInWitness)
			var btcAddress string
			if vin.ScriptSig.Hex == "" && len(vin.TxInWitness) > 0 {
				if len(vin.TxInWitness) >= 2 {
					btcAddress, _ = bitcoin.ExtractMultiAddress(vin.TxInWitness[1])
				} else {
					btcAddress, _ = bitcoin.ExtractNonMultiAddress(vin.TxInWitness[0])
				}
			} else {
				btcAddress, _ = bitcoin.ExtractAddressesFromVinScriptSigHex(vin.ScriptSig.Hex)
			}
			vinItem := &btc.Vin{
				Hash:     vin.TxId,
				Vout:     uint32(vin.Vout),
				Amount:   0,
				Address:  btcAddress,
				Sequence: vin.Sequence,
			}
			vinList = append(vinList, vinItem)
		}
		var voutList []*btc.Vout
		for _, vout := range rawTx.Vout {
			voutAmount := vout.Value * BtcDecimal
			voutItem := &btc.Vout{
				Address: vout.ScriptPubKey.Address,
				Amount:  uint64(voutAmount),
				Index:   uint32(vout.N),
				ScriptPubKey: &btc.ScriptPubKey{
					Asm:     vout.ScriptPubKey.Asm,
					Desc:    vout.ScriptPubKey.Desc,
					Hex:     vout.ScriptPubKey.Hex,
					Address: vout.ScriptPubKey.Address,
					Type:    vout.ScriptPubKey.Type,
				},
			}
			voutList = append(voutList, voutItem)
		}
		txItem := &btc.TransactionList{
			Hash: rawTx.Hash,
			Vin:  vinList,
			Vout: voutList,
		}
		txList = append(txList, txItem)
	}
	return &btc.BlockResponse{
		Code:   btc.ReturnCode_SUCCESS,
		Msg:    "get block by hash success",
		Height: resultBlock.Height,
		Hash:   req.Hash,
		TxList: txList,
	}, nil
}

func (wbs *WalletBtcService) GetBlockHeaderByHash(ctx context.Context, req *btc.BlockHeaderHashRequest) (*btc.BlockHeaderResponse, error) {
	hash, err := chainhash.NewHashFromStr(req.Hash)
	if err != nil {
		log.Error("format string to hash fail", "err", err)
	}
	blockHeader, err := wbs.btcClient.Client.GetBlockHeader(hash)
	if err != nil {
		return &btc.BlockHeaderResponse{
			Code: btc.ReturnCode_ERROR,
			Msg:  "get block header fail",
		}, err
	}
	return &btc.BlockHeaderResponse{
		Code:       btc.ReturnCode_SUCCESS,
		Msg:        "get block header success",
		PrevHash:   blockHeader.PrevBlock.String(),
		Number:     "nil",
		BlockHash:  req.Hash,
		MerkleRoot: blockHeader.MerkleRoot.String(),
		Time:       uint64(blockHeader.Timestamp.Unix()),
	}, nil
}

func (wbs *WalletBtcService) GetBlockHeaderByNumber(ctx context.Context, req *btc.BlockHeaderNumberRequest) (*btc.BlockHeaderResponse, error) {
	log.Info("start get block header by number")
	blockNumber := req.Height
	if req.Height == 0 {
		latestBlock, err := wbs.btcClient.Client.GetBlockCount()
		if err != nil {
			return &btc.BlockHeaderResponse{
				Code: btc.ReturnCode_ERROR,
				Msg:  "get latest block fail",
			}, err
		}
		log.Info("get block header success", "latestBlock", latestBlock)
		blockNumber = latestBlock
	}
	blockHash, err := wbs.btcClient.Client.GetBlockHash(blockNumber)
	if err != nil {
		log.Error("get block hash by number fail", "err", err)
		return &btc.BlockHeaderResponse{
			Code: btc.ReturnCode_ERROR,
			Msg:  "get block hash fail",
		}, err
	}
	log.Info("get block hash success", "blockHash", blockHash)
	blockHeader, err := wbs.btcClient.Client.GetBlockHeader(blockHash)
	if err != nil {
		return &btc.BlockHeaderResponse{
			Code: btc.ReturnCode_ERROR,
			Msg:  "get block header fail",
		}, err
	}
	return &btc.BlockHeaderResponse{
		Code:       btc.ReturnCode_SUCCESS,
		Msg:        "get block header success",
		PrevHash:   blockHeader.PrevBlock.String(),
		Number:     strconv.FormatInt(blockNumber, 10),
		BlockHash:  blockHash.String(),
		MerkleRoot: blockHeader.MerkleRoot.String(),
		Time:       uint64(blockHeader.Timestamp.Unix()),
	}, nil
}

func (wbs *WalletBtcService) SendTx(ctx context.Context, req *btc.SendTxRequest) (*btc.SendTxResponse, error) {
	r := bytes.NewReader([]byte(req.RawTx))
	var msgTx wire.MsgTx
	err := msgTx.Deserialize(r)
	if err != nil {
		return &btc.SendTxResponse{
			Code: btc.ReturnCode_ERROR,
			Msg:  err.Error(),
		}, err
	}
	txHash, err := wbs.btcClient.SendRawTransaction(&msgTx, true)
	if err != nil {
		return &btc.SendTxResponse{
			Code: btc.ReturnCode_ERROR,
			Msg:  err.Error(),
		}, err
	}
	if strings.Compare(msgTx.TxHash().String(), txHash.String()) != 0 {
		log.Error("broadcast transaction, tx hash mismatch", "local hash", msgTx.TxHash().String(), "hash from net", txHash.String(), "signedTx", req.RawTx)
	}
	return &btc.SendTxResponse{
		Code:   btc.ReturnCode_SUCCESS,
		Msg:    "send tx success",
		TxHash: txHash.String(),
	}, nil
}

func (wbs *WalletBtcService) GetTxByAddress(ctx context.Context, req *btc.TxAddressRequest) (*btc.TxAddressResponse, error) {
	transaction, err := wbs.thirdPartClient.GetTransactionsByAddress(req.Address, strconv.Itoa(int(req.Page)), strconv.Itoa(int(req.Pagesize)))
	if err != nil {
		return &btc.TxAddressResponse{
			Code: btc.ReturnCode_ERROR,
			Msg:  "get transaction list fail",
			Tx:   nil,
		}, err
	}
	var tx_list []*btc.TxMessage
	for _, ttxs := range transaction.Txs {
		var from_addrs []*btc.Address
		var to_addrs []*btc.Address
		var value_list []*btc.Value
		var direction int32
		for _, inputs := range ttxs.Inputs {
			from_addrs = append(from_addrs, &btc.Address{Address: inputs.PrevOut.Addr})
		}
		tx_fee := ttxs.Fee
		for _, out := range ttxs.Out {
			to_addrs = append(to_addrs, &btc.Address{Address: out.Addr})
			value_list = append(value_list, &btc.Value{Value: out.Value.String()})
		}
		datetime := ttxs.Time.String()
		if strings.EqualFold(req.Address, from_addrs[0].Address) {
			direction = 0
		} else {
			direction = 1
		}
		tx := &btc.TxMessage{
			Hash:     ttxs.Hash,
			Froms:    from_addrs,
			Tos:      to_addrs,
			Values:   value_list,
			Fee:      tx_fee.String(),
			Status:   btc.TxStatus_Success,
			Type:     direction,
			Height:   ttxs.BlockHeight.String(),
			Datetime: datetime,
		}
		tx_list = append(tx_list, tx)
	}
	return &btc.TxAddressResponse{
		Code: btc.ReturnCode_SUCCESS,
		Msg:  "get transaction list success",
		Tx:   tx_list,
	}, nil
}

func (wbs *WalletBtcService) GetTxByHash(ctx context.Context, req *btc.TxHashRequest) (*btc.TxHashResponse, error) {
	transaction, err := wbs.thirdPartClient.GetTransactionsByHash(req.Hash)
	if err != nil {
		return &btc.TxHashResponse{
			Code: btc.ReturnCode_ERROR,
			Msg:  "get transaction list fail",
			Tx:   nil,
		}, err
	}
	var from_addrs []*btc.Address
	var to_addrs []*btc.Address
	var value_list []*btc.Value
	for _, inputs := range transaction.Inputs {
		from_addrs = append(from_addrs, &btc.Address{Address: inputs.PrevOut.Addr})
	}
	tx_fee := transaction.Fee
	for _, out := range transaction.Out {
		to_addrs = append(to_addrs, &btc.Address{Address: out.Addr})
		value_list = append(value_list, &btc.Value{Value: out.Value.String()})
	}
	datetime := transaction.Time.String()
	txMsg := &btc.TxMessage{
		Hash:     transaction.Hash,
		Froms:    from_addrs,
		Tos:      to_addrs,
		Values:   value_list,
		Fee:      tx_fee.String(),
		Status:   btc.TxStatus_Success,
		Type:     0,
		Height:   transaction.BlockHeight.String(),
		Datetime: datetime,
	}
	return &btc.TxHashResponse{
		Code: btc.ReturnCode_SUCCESS,
		Msg:  "get transaction success",
		Tx:   txMsg,
	}, nil
}

func (wbs *WalletBtcService) BuildUnSignTransaction(ctx context.Context, req *btc.UnSignTransactionRequest) (*btc.UnSignTransactionResponse, error) {
	txHash, buf, err := wbs.CalcSignHashes(req.Vin, req.Vout)
	if err != nil {
		log.Error("calc sign hashes fail", "err", err)
		return nil, err
	}
	return &btc.UnSignTransactionResponse{
		Code:       btc.ReturnCode_SUCCESS,
		Msg:        "create un sign transaction success",
		TxData:     buf,
		SignHashes: txHash,
	}, nil
}

func (wbs *WalletBtcService) BuildSignedTransaction(ctx context.Context, req *btc.SignedTransactionRequest) (*btc.SignedTransactionResponse, error) {
	r := bytes.NewReader(req.TxData)
	var msgTx wire.MsgTx
	err := msgTx.Deserialize(r)
	if err != nil {
		log.Error("Create signed transaction msg tx deserialize", "err", err)
		return &btc.SignedTransactionResponse{
			Code: btc.ReturnCode_ERROR,
			Msg:  err.Error(),
		}, err
	}

	if len(req.Signatures) != len(msgTx.TxIn) {
		log.Error("CreateSignedTransaction invalid params", "err", "Signature number mismatch Txin number")
		err = errors.New("Signature number != Txin number")
		return &btc.SignedTransactionResponse{
			Code: btc.ReturnCode_ERROR,
			Msg:  err.Error(),
		}, err
	}

	if len(req.PublicKeys) != len(msgTx.TxIn) {
		log.Error("CreateSignedTransaction invalid params", "err", "Pubkey number mismatch Txin number")
		err = errors.New("Pubkey number != Txin number")
		return &btc.SignedTransactionResponse{
			Code: btc.ReturnCode_ERROR,
			Msg:  err.Error(),
		}, err
	}

	for i, in := range msgTx.TxIn {
		btcecPub, err2 := btcec.ParsePubKey(req.PublicKeys[i])
		if err2 != nil {
			log.Error("CreateSignedTransaction ParsePubKey", "err", err2)
			return &btc.SignedTransactionResponse{
				Code: btc.ReturnCode_ERROR,
				Msg:  err2.Error(),
			}, err2
		}
		var pkData []byte
		if btcec.IsCompressedPubKey(req.PublicKeys[i]) {
			pkData = btcecPub.SerializeCompressed()
		} else {
			pkData = btcecPub.SerializeUncompressed()
		}

		preTx, err2 := wbs.btcClient.GetRawTransactionVerbose(&in.PreviousOutPoint.Hash)
		if err2 != nil {
			log.Error("CreateSignedTransaction GetRawTransactionVerbose", "err", err2)
			return &btc.SignedTransactionResponse{
				Code: btc.ReturnCode_ERROR,
				Msg:  err2.Error(),
			}, err2
		}

		log.Info("CreateSignedTransaction ", "from address", preTx.Vout[in.PreviousOutPoint.Index].ScriptPubKey.Address)

		fromAddress, err2 := btcutil.DecodeAddress(preTx.Vout[in.PreviousOutPoint.Index].ScriptPubKey.Address, &chaincfg.MainNetParams)
		if err2 != nil {
			log.Error("CreateSignedTransaction DecodeAddress", "err", err2)
			return &btc.SignedTransactionResponse{
				Code: btc.ReturnCode_ERROR,
				Msg:  err2.Error(),
			}, err2
		}
		fromPkScript, err2 := txscript.PayToAddrScript(fromAddress)
		if err2 != nil {
			log.Error("CreateSignedTransaction PayToAddrScript", "err", err2)
			return &btc.SignedTransactionResponse{
				Code: btc.ReturnCode_ERROR,
				Msg:  err2.Error(),
			}, err2
		}

		if len(req.Signatures[i]) < 64 {
			err2 = errors.New("Invalid signature length")
			return &btc.SignedTransactionResponse{
				Code: btc.ReturnCode_ERROR,
				Msg:  err2.Error(),
			}, err2
		}
		var r *btcec.ModNScalar
		R := r.SetInt(r.SetBytes((*[32]byte)(req.Signatures[i][0:32])))
		var s *btcec.ModNScalar
		S := s.SetInt(r.SetBytes((*[32]byte)(req.Signatures[i][32:64])))
		btcecSig := ecdsa.NewSignature(R, S)
		sig := append(btcecSig.Serialize(), byte(txscript.SigHashAll))
		sigScript, err2 := txscript.NewScriptBuilder().AddData(sig).AddData(pkData).Script()
		if err2 != nil {
			log.Error("create signed transaction new script builder", "err", err2)
			return &btc.SignedTransactionResponse{
				Code: btc.ReturnCode_ERROR,
				Msg:  err2.Error(),
			}, err2
		}
		msgTx.TxIn[i].SignatureScript = sigScript
		amount := btcToSatoshi(preTx.Vout[in.PreviousOutPoint.Index].Value).Int64()
		log.Info("CreateSignedTransaction ", "amount", preTx.Vout[in.PreviousOutPoint.Index].Value, "int amount", amount)

		vm, err2 := txscript.NewEngine(fromPkScript, &msgTx, i, txscript.StandardVerifyFlags, nil, nil, amount, nil)
		if err2 != nil {
			log.Error("create signed transaction newEngine", "err", err2)
			return &btc.SignedTransactionResponse{
				Code: btc.ReturnCode_ERROR,
				Msg:  err2.Error(),
			}, err2
		}
		if err3 := vm.Execute(); err3 != nil {
			log.Error("CreateSignedTransaction NewEngine Execute", "err", err3)
			return &btc.SignedTransactionResponse{
				Code: btc.ReturnCode_ERROR,
				Msg:  err3.Error(),
			}, err3
		}
	}
	// serialize tx
	buf := bytes.NewBuffer(make([]byte, 0, msgTx.SerializeSize()))
	err = msgTx.Serialize(buf)
	if err != nil {
		log.Error("CreateSignedTransaction tx Serialize", "err", err)
		return &btc.SignedTransactionResponse{
			Code: btc.ReturnCode_ERROR,
			Msg:  err.Error(),
		}, err
	}

	hash := msgTx.TxHash()
	return &btc.SignedTransactionResponse{
		Code:         btc.ReturnCode_SUCCESS,
		SignedTxData: buf.Bytes(),
		Hash:         (&hash).CloneBytes(),
	}, nil
}

func (wbs *WalletBtcService) DecodeTransaction(ctx context.Context, req *btc.DecodeTransactionRequest) (*btc.DecodeTransactionResponse, error) {
	res, err := wbs.DecodeTx(req.RawData, req.Vins, false)
	if err != nil {
		log.Info("decode tx fail", "err", err)
		return &btc.DecodeTransactionResponse{
			Code: btc.ReturnCode_ERROR,
			Msg:  err.Error(),
		}, err
	}
	return &btc.DecodeTransactionResponse{
		Code:       btc.ReturnCode_SUCCESS,
		Msg:        "decode transaction response",
		SignHashes: res.SignHashes,
		Status:     btc.TxStatus_Other,
		Vins:       res.Vins,
		Vouts:      res.Vouts,
		CostFee:    res.CostFee.String(),
	}, nil
}

func (wbs *WalletBtcService) VerifySignedTransaction(ctx context.Context, req *btc.VerifyTransactionRequest) (*btc.VerifyTransactionResponse, error) {
	_, err := wbs.DecodeTx([]byte(""), nil, true)
	if err != nil {
		return &btc.VerifyTransactionResponse{
			Code: btc.ReturnCode_ERROR,
			Msg:  err.Error(),
		}, err
	}
	return &btc.VerifyTransactionResponse{
		Code:   btc.ReturnCode_SUCCESS,
		Msg:    "verify transaction success",
		Verify: true,
	}, nil
}

func (wbs *WalletBtcService) CalcSignHashes(Vins []*btc.Vin, Vouts []*btc.Vout) ([][]byte, []byte, error) {
	if len(Vins) == 0 || len(Vouts) == 0 {
		return nil, nil, errors.New("invalid len in or out")
	}
	rawTx := wire.NewMsgTx(wire.TxVersion)
	for _, in := range Vins {
		utxoHash, err := chainhash.NewHashFromStr(in.Hash)
		if err != nil {
			return nil, nil, err
		}
		txIn := wire.NewTxIn(wire.NewOutPoint(utxoHash, in.Vout), nil, nil)
		rawTx.AddTxIn(txIn)
	}
	for _, out := range Vouts {
		toAddress, err := btcutil.DecodeAddress(out.Address, &chaincfg.MainNetParams)
		if err != nil {
			return nil, nil, err
		}
		toPkScript, err := txscript.PayToAddrScript(toAddress)
		if err != nil {
			return nil, nil, err
		}
		rawTx.AddTxOut(wire.NewTxOut(1, toPkScript))
	}
	log.Info("raw Transaction", "rawTx", rawTx.SerializeSize())

	signHashes := make([][]byte, len(Vins))
	for i, in := range Vins {
		from := in.Address
		fromAddr, err := btcutil.DecodeAddress(from, &chaincfg.MainNetParams)
		if err != nil {
			log.Info("decode address error", "from", from, "err", err)
			return nil, nil, err
		}
		fromPkScript, err := txscript.PayToAddrScript(fromAddr)
		if err != nil {
			log.Info("pay to addr script err", "err", err)
			return nil, nil, err
		}
		signHash, err := txscript.CalcSignatureHash(fromPkScript, txscript.SigHashAll, rawTx, i)
		if err != nil {
			log.Info("Calc signature hash error", "err", err)
			return nil, nil, err
		}
		log.Info("Build sign hash", "signHashHex", hex.EncodeToString(signHash))
		signHashes[i] = signHash
	}
	log.Info("Build transaction success", "rawTx", rawTx.SerializeSize(), "signHashes", signHashes)
	buf := bytes.NewBuffer(make([]byte, 0, rawTx.SerializeSize()))
	return signHashes, buf.Bytes(), nil
}

func (wbs *WalletBtcService) DecodeTx(txData []byte, vins []*btc.Vin, sign bool) (*DecodeTxRes, error) {
	var msgTx wire.MsgTx
	err := msgTx.Deserialize(bytes.NewReader(txData))
	if err != nil {
		return nil, err
	}

	offline := true
	if len(vins) == 0 {
		offline = false
	}
	if offline && len(vins) != len(msgTx.TxIn) {
		return nil, errors.New("the length of deserialized tx's in differs from vin")
	}

	ins, totalAmountIn, err := wbs.DecodeVins(msgTx, offline, vins, sign)
	if err != nil {
		return nil, err
	}

	outs, totalAmountOut, err := wbs.DecodeVouts(msgTx)
	if err != nil {
		return nil, err
	}

	signHashes, _, err := wbs.CalcSignHashes(ins, outs)
	if err != nil {
		return nil, err
	}
	res := DecodeTxRes{
		SignHashes: signHashes,
		Vins:       ins,
		Vouts:      outs,
		CostFee:    totalAmountIn.Sub(totalAmountIn, totalAmountOut),
	}
	if sign {
		res.Hash = msgTx.TxHash().String()
	}
	return &res, nil
}

func (wbs *WalletBtcService) DecodeVins(msgTx wire.MsgTx, offline bool, vins []*btc.Vin, sign bool) ([]*btc.Vin, *big.Int, error) {
	ins := make([]*btc.Vin, 0, len(msgTx.TxIn))
	totalAmountIn := big.NewInt(0)
	for index, in := range msgTx.TxIn {
		vin, err := wbs.GetVin(offline, vins, index, in)
		if err != nil {
			return nil, nil, err
		}

		if sign {
			err = wbs.VerifySign(vin, msgTx, index)
			if err != nil {
				return nil, nil, err
			}
		}
		totalAmountIn.Add(totalAmountIn, big.NewInt(int64(vin.Amount)))
		ins = append(ins, vin)
	}
	return ins, totalAmountIn, nil
}

func (wbs *WalletBtcService) DecodeVouts(msgTx wire.MsgTx) ([]*btc.Vout, *big.Int, error) {
	outs := make([]*btc.Vout, 0, len(msgTx.TxOut))
	totalAmountOut := big.NewInt(0)
	for _, out := range msgTx.TxOut {
		var t btc.Vout
		_, pubkeyAddrs, _, err := txscript.ExtractPkScriptAddrs(out.PkScript, &chaincfg.MainNetParams)
		if err != nil {
			return nil, nil, err
		}
		t.Address = pubkeyAddrs[0].EncodeAddress()
		t.Amount = 1
		totalAmountOut.Add(totalAmountOut, big.NewInt(1))
		outs = append(outs, &t)
	}
	return outs, totalAmountOut, nil
}

func (wbs *WalletBtcService) GetVin(offline bool, vins []*btc.Vin, index int, in *wire.TxIn) (*btc.Vin, error) {
	var vin *btc.Vin
	if offline {
		vin = vins[index]
	} else {
		preTx, err := wbs.btcClient.GetRawTransactionVerbose(&in.PreviousOutPoint.Hash)
		if err != nil {
			return nil, err
		}
		out := preTx.Vout[in.PreviousOutPoint.Index]
		vin = &btc.Vin{
			Hash:    "",
			Vout:    0,
			Amount:  btcToSatoshi(out.Value).Uint64(),
			Address: out.ScriptPubKey.Address,
		}
	}
	vin.Hash = in.PreviousOutPoint.Hash.String()
	vin.Vout = in.PreviousOutPoint.Index
	return vin, nil
}

func (wbs *WalletBtcService) VerifySign(vin *btc.Vin, msgTx wire.MsgTx, index int) error {
	fromAddress, err := btcutil.DecodeAddress(vin.Address, &chaincfg.MainNetParams)
	if err != nil {
		return err
	}

	fromPkScript, err := txscript.PayToAddrScript(fromAddress)
	if err != nil {
		return err
	}

	vm, err := txscript.NewEngine(fromPkScript, &msgTx, index, txscript.StandardVerifyFlags, nil, nil, int64(vin.Amount), nil)
	if err != nil {
		return err
	}
	return vm.Execute()
}
