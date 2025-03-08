package config

import (
	"os"

	"gopkg.in/yaml.v2"

	"github.com/ethereum/go-ethereum/log"
)

type Server struct {
	EndPoint string `yaml:"end_point"`
	Port     string `yaml:"port"`
}

type BtcNode struct {
	RpcUrl       string `yaml:"rpc_url"`
	RpcUser      string `yaml:"rpc_user"`
	RpcPass      string `yaml:"rpc_pass"`
	DataApiUrl   string `yaml:"data_api_url"`
	DataApiKey   string `yaml:"data_api_key"`
	DataApiToken string `yaml:"data_api_token"`
	TpApiUrl     string `yaml:"tp_api_url"`
	TimeOut      uint64 `yaml:"time_out"`
}

type Config struct {
	Server  Server  `yaml:"server"`
	BtcNode BtcNode `yaml:"walletnode"`
	NetWork string  `yaml:"network"`
}

func New(path string) (*Config, error) {
	var config = new(Config)
	h := log.NewTerminalHandler(os.Stdout, true)
	log.SetDefault(log.NewLogger(h))
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(data, config)
	if err != nil {
		return nil, err
	}
	return config, nil
}
