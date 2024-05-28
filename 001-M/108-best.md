Happy Aegean Crab

high

# `setStartBlock()` doesn't change the block at which already existing pools will start accumulating points

## Summary
The function [setStartBlock()](https://github.com/sherlock-audit/2024-05-sophon/blob/main/farming-contracts/contracts/farm/SophonFarming.sol#L272) can be called by the owner to change the block number at which points will start accumulating. When it's called, the block at which already existing pools will start accumulating points will not change. Already existing pools will:
1. Start accumulating points from the old `startBlock` if the new `startBlock` is set after the old one.
2. Not accumulate rewards until the old `startBlock` is reached if the new `startBlock` is set before the old one.

## Vulnerability Detail
This happens because [updatePool()](https://github.com/sherlock-audit/2024-05-sophon/blob/main/farming-contracts/contracts/farm/SophonFarming.sol#L411) considers the pool `lastRewardBlock` as the block number from which points should start accumulating and [setStartBlock()](https://github.com/sherlock-audit/2024-05-sophon/blob/main/farming-contracts/contracts/farm/SophonFarming.sol#L272) never updates the `lastRewardBlock` of the already existing pools to the new `startBlock`.

### POC
Runnable POC that showcases point `1` explained above. Can be copy-pasted in `SophonFarming.t.sol`:
```solidity
function test_SettingStartBlockDoesntUpdatePools() public {
    address alice = makeAddr("alice");
    uint256 amountToDeposit = sDAI.convertToAssets(1e18);

    vm.prank(alice);
    dai.approve(address(sophonFarming), type(uint256).max);
    deal(address(dai), alice, amountToDeposit);

    //-> Pools original `startBlock` is `1`
    //-> Admin changes `startBlock` to `100`
    vm.prank(deployer);
    sophonFarming.setStartBlock(100);

    //-> Alice deposits at block `90`, which is after the previous `startBlock` (1) but before the current `startBlock` (100)
    vm.roll(90);
    vm.prank(alice);
    sophonFarming.depositDai(amountToDeposit, 0);

    //-> After 9 blocks, at block `99`, Alice has accumulated rewards but she shouldn't have because the current `startBlock` (100) has not been reached yet
    vm.roll(99);
    vm.prank(alice);
    sophonFarming.withdraw(0, type(uint256).max);
    assertEq(sophonFarming.pendingPoints(0, alice), 74999999999999999999);
}
```

Can be run with:
```bash
forge test --match-test test_SettingStartBlockDoesntUpdatePools -vvvvv
```

## Impact
When [setStartBlock()](https://github.com/sherlock-audit/2024-05-sophon/blob/main/farming-contracts/contracts/farm/SophonFarming.sol#L272) is called the block at which already existing pools will start accumulating points will not change.

## Code Snippet

## Tool used

Manual Review

## Recommendation
In [setStartBlock()](https://github.com/sherlock-audit/2024-05-sophon/blob/main/farming-contracts/contracts/farm/SophonFarming.sol#L272) loop over all of the existing pools and adjust each pool `lastRewardBlock` to the new `startBlock`. Furthermore  [setStartBlock()](https://github.com/sherlock-audit/2024-05-sophon/blob/main/farming-contracts/contracts/farm/SophonFarming.sol#L272) should revert if the new `startBlock` is lower than the current `block.number` as this would create problems in points distribution accounting if the above fix is implemented.
