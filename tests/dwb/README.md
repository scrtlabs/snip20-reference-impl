# DWB Integration Test Suite

## Requirements
The test suite is run using [bun](https://bun.sh/).

## Setup
From this directory:
```sh
bun install
cp .env.example .env
```

Edit the `.env` file (or leave as is) to configure the network to either your localsecret or pulsar-3.

## Run
```sh
bun run test  ## compiles the contract for integration tests and runs the main test suite
```


## Debugging

In case there is a silent failure, it may help to run the suite using node.js instead of bun. You can compile it and run it and debug it interactively with the following commands:
```sh
bun run build && node --env-file=.env --inspect-brk dist/main.js
```

The console output should look something like this:
![Integration test preview](https://github.com/user-attachments/assets/be2fedda-550c-45e6-aee4-5af45a84d5b8)
