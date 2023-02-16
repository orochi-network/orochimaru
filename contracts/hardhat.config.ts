import fs from 'fs';
import { HardhatUserConfig } from 'hardhat/types';
import { env } from './env';
import '@nomicfoundation/hardhat-toolbox';

if (fs.existsSync('./typechain-types')) {
  const dir = fs.opendirSync(`${__dirname}/tasks`);
  for (let entry = dir.readSync(); entry !== null; entry = dir.readSync()) {
    if (entry.name.toLowerCase().includes('.ts')) {
      // eslint-disable-next-line import/no-dynamic-require
      require(`./tasks/${entry.name.replace(/\.ts$/gi, '')}`);
    }
  }
}

const compilers = ['0.8.17'].map((item: string) => ({
  version: item,
  settings: {
    optimizer: {
      enabled: true,
      runs: 200,
    },
  },
}));

const config: HardhatUserConfig = {
  defaultNetwork: 'hardhat',
  gasReporter: {
    enabled: true,
  },
  networks: {
    ethereum: {
      url: 'https://eth-mainnet.public.blastapi.io',
      chainId: 1,
      accounts: {
        mnemonic: env.OROCHI_MNEMONIC,
        path: "m/44'/60'/0'/0",
      },
    },
    bnbChain: {
      url: 'https://bsc-dataseed3.binance.org',
      chainId: 56,
      accounts: {
        mnemonic: env.OROCHI_MNEMONIC,
        path: "m/44'/60'/0'/0",
      },
    },
    bnbChainTest: {
      url: 'https://data-seed-prebsc-1-s1.binance.org:8545',
      chainId: 97,
      accounts: {
        mnemonic: env.OROCHI_MNEMONIC,
        path: "m/44'/60'/0'/0",
      },
    },
    // Hard hat network
    hardhat: {
      chainId: 911,
      hardfork: 'london',
      blockGasLimit: 30000000,
      initialBaseFeePerGas: 0,
      gas: 25000000,
      accounts: {
        mnemonic: env.OROCHI_MNEMONIC,
        path: "m/44'/60'/0'/0",
      },
      // Are we going to forking mainnet for testing?
      forking: env.OROCHI_FORK
        ? {
            url: env.OROCHI_RPC,
            enabled: true,
          }
        : undefined,
    },
  },
  solidity: {
    compilers,
  },
};

export default config;
