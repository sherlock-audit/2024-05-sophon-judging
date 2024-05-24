Joyful Wintergreen Alligator

high

# Many cases `stEth::transferFrom` will transfer 1-2 less way, which would result in revert in consequent functions, because of not enough balance

## Summary
When user calls `depositStEth`, he passes `_amount` param, which is set to `IERC20(stETH).safeTransferFrom()` func and then the sam `_amount` is passed down the chain:
```solidity
        IERC20(stETH).safeTransferFrom(
            msg.sender,
            address(this),
            _amount
        );

        _depositPredefinedAsset(_amount, _amount, _boostAmount, PredefinedPool.wstETH);
 ```
## Vulnerability Detail
The probability of issue appearing is high and you can check in the following discussion. It has also been classified as a High severity on past contests:
https://github.com/lidofinance/lido-dao/issues/442

`stETH` is using shares for tracking balances and it is a known issue that due to rounding error, transferred shares may be 1-2 wei less than `_amount` passed.
This would revert on the following line as we have transferred `_amount - 1` and farming contract do not hold `stEth` funds:
```solidity
    function _stEthTOwstEth(uint256 _amount) internal returns (uint256) {
        // wrap returns exact amount of wstETH
        return IwstETH(wstETH).wrap(_amount);
    }
```
The impact may be bigger if the staking contract is implemented by 3rd party protocol and expect this the function to be always fine.
## Impact
- Contract functionality DoS 

## Code Snippet
https://github.com/sherlock-audit/2024-05-sophon/blob/05059e53755f24ae9e3a3bb2996de15df0289a6c/farming-contracts/contracts/farm/SophonFarming.sol#L474-L478
## Tool used

Manual Review

## Recommendation
Use lido recommendation to utilize `transferShares` function, so the `_amount` is realistic, or implement FoT approach, which compares the balance before and after the transfer. 