package flags

import "github.com/urfave/cli/v2"

const evnVarPrefix = "BTC"

func prefixEnvVars(name string) []string {
	return []string{evnVarPrefix + "_" + name}
}

var (
	EndpointFlag = &cli.StringFlag{
		Name:     "endpoint",
		Usage:    "The host of the rpc endpoint",
		EnvVars:  prefixEnvVars("ENDPOINT"),
		Required: true,
	}
	PortFlag = &cli.StringFlag{
		Name:     "port",
		Usage:    "The port of the rpc services",
		EnvVars:  prefixEnvVars("PORT"),
		Required: true,
	}
	RpcUrlFlag = &cli.StringFlag{
		Name:     "rpc-url",
		Usage:    "The host of the btc rpc url",
		EnvVars:  prefixEnvVars("RPC_URL"),
		Required: true,
	}
	RpcUserFlag = &cli.StringFlag{
		Name:     "rpc-user",
		Usage:    "The user of the btc rpc",
		EnvVars:  prefixEnvVars("RPC_USER"),
		Required: true,
	}
	RpcPassFlag = &cli.StringFlag{
		Name:     "rpc-pass",
		Usage:    "The password of the btc rpc",
		EnvVars:  prefixEnvVars("RPC_PASS"),
		Required: true,
	}
	DataApiUrlFlag = &cli.StringFlag{
		Name:     "data-api-url",
		Usage:    "The data api url of the btc data platform",
		EnvVars:  prefixEnvVars("DATA_API_URL"),
		Required: true,
	}
	DataApiKeyFlag = &cli.StringFlag{
		Name:     "data-api-key",
		Usage:    "The data api key of the btc data platform",
		EnvVars:  prefixEnvVars("DATA_API_KEY"),
		Required: true,
	}
	DataApiTokenFlag = &cli.StringFlag{
		Name:     "data-api-token",
		Usage:    "The data api token of the btc data platform",
		EnvVars:  prefixEnvVars("DATA_API_TOKEN"),
		Required: true,
	}
	TpApiUrlFlag = &cli.StringFlag{
		Name:     "tp-api-url",
		Usage:    "The data api token of the btc data platform",
		EnvVars:  prefixEnvVars("TP_API_URL"),
		Required: true,
	}
	TimeOutFlag = &cli.DurationFlag{
		Name:     "timeout",
		Usage:    "The timeout the btc rpc",
		EnvVars:  prefixEnvVars("TIMEOUT"),
		Required: true,
	}

	// HttpHostFlag RPC Service
	HttpHostFlag = &cli.StringFlag{
		Name:     "http-host",
		Usage:    "The host of the http",
		EnvVars:  prefixEnvVars("HTTP_HOST"),
		Required: true,
	}
	HttpPortFlag = &cli.IntFlag{
		Name:     "http-port",
		Usage:    "The port of the http",
		EnvVars:  prefixEnvVars("HTTP_PORT"),
		Required: true,
	}

	MetricsHostFlag = &cli.StringFlag{
		Name:    "metric-host",
		Usage:   "The host of the metric",
		EnvVars: prefixEnvVars("METRIC_HOST"),
		Value:   "127.0.0.1",
	}
	MetricsPortFlag = &cli.IntFlag{
		Name:    "metric-port",
		Usage:   "The port of the metric",
		EnvVars: prefixEnvVars("METRIC_PORT"),
		Value:   9091,
	}
	NetWorkFlag = &cli.StringFlag{
		Name:    "network",
		Usage:   "mainnet or testnet config",
		EnvVars: prefixEnvVars("NETWORK"),
		Value:   "mainnet",
	}
)

var requireFlags = []cli.Flag{
	EndpointFlag,
	PortFlag,
	RpcUrlFlag,
	RpcUserFlag,
	RpcPassFlag,
	DataApiUrlFlag,
	DataApiKeyFlag,
	DataApiTokenFlag,
	TpApiUrlFlag,
	TimeOutFlag,
	HttpHostFlag,
	HttpPortFlag,
}

var optionalFlags = []cli.Flag{
	MetricsHostFlag,
	MetricsPortFlag,
	NetWorkFlag,
}

func init() {
	Flags = append(requireFlags, optionalFlags...)
}

var Flags []cli.Flag
