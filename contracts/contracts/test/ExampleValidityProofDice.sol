// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;
import '@openzeppelin/contracts/access/Ownable.sol';
import '../interfaces/IOrandConsumerV1.sol';

error WrongGuessingValue(uint128 guessing);

// Application should be an implement of IOrandConsumerV1 interface
contract ExampleValidityProofDice is IOrandConsumerV1, Ownable {
  // Set new provider
  event SetProvider(address indexed oldProvider, address indexed newProvider);

  // Fulfill awaiting result
  event Fulfill(uint256 indexed gameId, uint256 guessed, uint256 indexed result);

  // New guess from player
  event NewGuess(address indexed player, uint256 indexed gameId, uint128 indexed guessed);

  // Adjust maximum batching
  event AdjustMaximumBatching(uint256 indexed maximum);

  // Game structure
  struct Game {
    uint128 guessed;
    uint128 result;
  }

  // Provider address
  address private orandProviderV1;

  // Game result storage
  mapping(uint256 => Game) private gameResult;

  // Total game
  uint256 private totalGame;

  // Fulfiled randomness
  uint256 private fulfilled;

  // We batching the radomness in one epoch
  uint256 private maximumBatching;

  // Only allow Orand to submit result
  modifier onlyOrandProviderV1() {
    if (msg.sender != orandProviderV1) {
      revert InvalidProvider();
    }
    _;
  }

  // Constructor
  constructor(address provider, uint256 limitBatching) {
    _setProvider(provider);
    _setBatching(limitBatching);
  }

  //=======================[  Internal  ]====================

  // Set provider
  function _setProvider(address provider) internal {
    emit SetProvider(orandProviderV1, provider);
    orandProviderV1 = provider;
  }

  // Set provider
  function _getProvider() internal view returns (address) {
    return orandProviderV1;
  }

  // Set max batching
  function _setBatching(uint256 maximum) internal {
    maximumBatching = maximum;
    emit AdjustMaximumBatching(maximum);
  }

  //=======================[  Owner  ]====================

  // Set provider
  function setProvider(address provider) external onlyOwner returns (bool) {
    _setProvider(provider);
    return true;
  }

  // Set provider
  function setMaximumBatching(uint256 maximum) external onlyOwner returns (bool) {
    _setBatching(maximum);
    return true;
  }

  //=======================[  OrandProviderV1  ]====================

  // Consume the result of Orand V1 with batching feature
  function consumeRandomness(uint256 randomness) external override onlyOrandProviderV1 returns (bool) {
    uint256 filling = fulfilled;
    uint256 processing = totalGame;

    // We keep batching < maximumBatching
    if (processing - filling > maximumBatching) {
      processing = filling + maximumBatching;
    } else {
      processing = totalGame;
    }

    // Starting batching
    for (; filling < processing; filling += 1) {
      gameResult[filling].result = uint128((randomness % 6) + 1);
      randomness = uint256(keccak256(abi.encodePacked(randomness)));
      emit Fulfill(filling, gameResult[filling].guessed, gameResult[filling].result);
    }

    fulfilled = filling - 1;
    return true;
  }

  //=======================[  External  ]====================

  // Player can guessing any number in range of 1-6
  function guessingDiceNumber(uint128 guessing) external returns (bool) {
    // Player only able to guessing between 1-6 since it's dice number
    if (guessing < 1 || guessing > 6) {
      revert WrongGuessingValue(guessing);
    }
    Game memory currentGame = Game({ guessed: guessing, result: 0 });
    gameResult[totalGame] = currentGame;
    emit NewGuess(msg.sender, totalGame, guessing);
    totalGame += 1;
    return true;
  }

  //=======================[  External View  ]====================

  // Get result from smart contract
  function getResult(uint256 gameId) external view returns (Game memory result) {
    return gameResult[gameId];
  }

  function getStateOfGame() external view returns (uint256 fulfill, uint256 total) {
    return (fulfilled, totalGame);
  }
}
