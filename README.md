<!--
parent:
  order: false
-->

<div align="center">
  <h1> wallet-chain-btc repo </h1>
</div>

<div align="center">
  <a href="https://github.com/dapplink-labs/wallet-chain-btc/releases/latest">
    <img alt="Version" src="https://img.shields.io/github/tag/dapplink-labs/wallet-chain-btc.svg" />
  </a>
  <a href="https://github.com/dapplink-labs/wallet-chain-btc/blob/main/LICENSE">
    <img alt="License: Apache-2.0" src="https://img.shields.io/github/license/dapplink-labs/wallet-chain-btc.svg" />
  </a>
  <a href="https://pkg.go.dev/github.com/dapplink-labs/wallet-chain-btc">
    <img alt="GoDoc" src="https://godoc.org/github.com/dapplink-labs/wallet-chain-btc?status.svg" />
  </a>
</div>

This repo is account model chains rpc service gateway. currently support Bitcoin, written in golang, provides grpc interface for upper-layer service access

**Tips**: need [Go 1.22+](https://golang.org/dl/)

## Install

### Install dependencies
```bash
go mod tidy
```
### build
```
make 
```

### start
```
source .env
```

### Start the RPC interface test interface

```bash
grpcui -plaintext 127.0.0.1:8189
```

## Contribute

### 1.fork repo

fork wallet-chain-btc to your github

### 2.clone repo

```bash
git@github.com:guoshijiang/wallet-chain-btc.git
```

### 3. create new branch and commit code

```bash
git branch -C xxx
git checkout xxx

coding

git add .
git commit -m "xxx"
git push origin xxx
```

### 4.commit PR

Have a pr on your github and submit it to the wallet-chain-btc repository

### 5.review

After the wallet-chain-btc code maintainer has passed the review, the code will be merged into the wallet-chain-btc library. At this point, your PR submission is complete

### 6.Disclaimer

This code has not yet been audited, and should not be used in any production systems.
