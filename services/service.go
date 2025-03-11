package services

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/dapplink-labs/wallet-chain-btc/bitcoin"
	"github.com/dapplink-labs/wallet-chain-btc/bitcoin/base"
	"github.com/dapplink-labs/wallet-chain-btc/config"
	"github.com/dapplink-labs/wallet-chain-btc/proto/btc"
)

const MaxRecvMessageSize = 1024 * 1024 * 30000

type WalletBtcService struct {
	RpcEndPoint     string
	RpcPort         string
	btcClient       *base.BaseClient
	btcDataClient   *base.BaseDataClient
	thirdPartClient *bitcoin.BcClient

	btc.UnimplementedWalletBtcServiceServer
	stopped atomic.Bool
}

func NewBitcoinRpcService(conf *config.Config) (*WalletBtcService, error) {
	log.Info("Config info", "RpcUrl", conf.BtcNode.RpcUrl, "RpcUser", conf.BtcNode.RpcUser, "RpcPass", conf.BtcNode.RpcPass)
	baseClient, err := base.NewBaseClient(conf.BtcNode.RpcUrl, conf.BtcNode.RpcUser, conf.BtcNode.RpcPass)
	if err != nil {
		log.Error("new bitcoin rpc client fail", "err", err)
		return nil, err
	}
	baseDataClient, err := base.NewBaseDataClient(conf.BtcNode.DataApiUrl, conf.BtcNode.DataApiKey, "BTC", "Bitcoin")
	if err != nil {
		log.Error("new bitcoin data client fail", "err", err)
		return nil, err
	}
	bcClient, err := bitcoin.NewBlockChainClient(conf.BtcNode.TpApiUrl)
	if err != nil {
		log.Error("new blockchain client fail", "err", err)
		return nil, err
	}
	return &WalletBtcService{
		RpcEndPoint:     conf.Server.EndPoint,
		RpcPort:         conf.Server.Port,
		btcClient:       baseClient,
		btcDataClient:   baseDataClient,
		thirdPartClient: bcClient,
	}, nil
}

func (wbs *WalletBtcService) Start(ctx context.Context) error {
	go func(wbs *WalletBtcService) {
		rpcAddr := fmt.Sprintf("%s:%s", wbs.RpcEndPoint, wbs.RpcPort)
		log.Info("Rpc address", "rpcAddr", rpcAddr)
		listener, err := net.Listen("tcp", rpcAddr)
		if err != nil {
			log.Error("Could not start tcp listener. ")
		}

		opt := grpc.MaxRecvMsgSize(MaxRecvMessageSize)

		gs := grpc.NewServer(
			opt,
			grpc.ChainUnaryInterceptor(
				nil,
			),
		)

		reflection.Register(gs)

		btc.RegisterWalletBtcServiceServer(gs, wbs)

		log.Info("grpc info", "addr", listener.Addr())

		if err := gs.Serve(listener); err != nil {
			log.Error("start rpc server fail", "err", err)
		}
	}(wbs)
	return nil
}

func (wbs *WalletBtcService) Stop(ctx context.Context) error {
	wbs.stopped.Store(true)
	return nil
}

func (wbs *WalletBtcService) Stopped() bool {
	return wbs.stopped.Load()
}
