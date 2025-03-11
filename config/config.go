package config

import (
	"time"

	"github.com/urfave/cli/v2"

	"github.com/dapplink-labs/wallet-chain-btc/flags"
)

type Server struct {
	EndPoint string
	Port     string
}

type BtcNode struct {
	RpcUrl       string
	RpcUser      string
	RpcPass      string
	DataApiUrl   string
	DataApiKey   string
	DataApiToken string
	TpApiUrl     string
	TimeOut      time.Duration
}

type Config struct {
	Server  Server
	BtcNode BtcNode
	NetWork string
}

func NewConfig(ctx *cli.Context) Config {
	return Config{
		Server: Server{
			EndPoint: ctx.String(flags.EndpointFlag.Name),
			Port:     ctx.String(flags.PortFlag.Name),
		},
		BtcNode: BtcNode{
			RpcUrl:       ctx.String(flags.RpcUrlFlag.Name),
			RpcUser:      ctx.String(flags.RpcUserFlag.Name),
			RpcPass:      ctx.String(flags.RpcPassFlag.Name),
			DataApiUrl:   ctx.String(flags.DataApiUrlFlag.Name),
			DataApiKey:   ctx.String(flags.DataApiKeyFlag.Name),
			DataApiToken: ctx.String(flags.DataApiTokenFlag.Name),
			TpApiUrl:     ctx.String(flags.TpApiUrlFlag.Name),
			TimeOut:      ctx.Duration(flags.TimeOutFlag.Name),
		},
		NetWork: ctx.String(flags.NetWorkFlag.Name),
	}
}
