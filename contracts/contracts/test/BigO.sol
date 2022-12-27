// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;
import '@openzeppelin/contracts/token/ERC20/ERC20.sol';

contract BigO is ERC20 {
  constructor() ERC20('BigO', 'O') {
    _mint(tx.origin, 1000000000000 * (10 ** decimals()));
  }
}
