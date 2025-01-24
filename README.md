# Verified ERC20 State

This repository contains code to fully rebuild ERC20 contracts memory using geth api and incrementally verify the 
contract state using flashbots/eth-sparse-mpt .


# How to run

First, create a .env file with the any geth compatible api server url, for instance:

```
GETH_URL=https://eth-mainnet.g.alchemy.com/v2/your_api_key
```

Then just run the code:
```
  cargo run
```

# How to use in other packages

Take a look at src/lib.rs

You can also find a usage example in https://github.com/obliviouslabs/oblivious-erc20-state

