/* eslint-disable no-await-in-loop */
import '@nomiclabs/hardhat-ethers';
import { task } from 'hardhat/config';
import { HardhatRuntimeEnvironment } from 'hardhat/types';
import { Deployer } from '../helpers';
import { ExampleValidityProofDice } from '../typechain-types';

task('deploy:example', 'Deploy dice example contract').setAction(
  async (_taskArgs: any, hre: HardhatRuntimeEnvironment) => {
    const accounts = await hre.ethers.getSigners();
    const deployer: Deployer = Deployer.getInstance(hre).connect(accounts[0]);
    let deployedProvider;
    if (hre.network.name == 'bnbChainTest') {
      deployedProvider = '0x75C0e60Ca5771dd58627ac8c215661d0261D5D76';
    }
    let diceGame = <ExampleValidityProofDice>(
      await deployer.contractDeploy('OrandV1/ExampleValidityProofDice', [], deployedProvider, 250)
    );
    for (let i = 0; i < 10; i += 1) {
      (await diceGame.guessingDiceNumber((Math.round(Math.random() * 10) % 6) + 1)).wait(5);
    }
    deployer.printReport();
  },
);

export default {};
