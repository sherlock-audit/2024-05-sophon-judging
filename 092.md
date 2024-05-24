Striped Orchid Donkey

medium

# Protocol won't be eligible for referral rewards for depositing ETH

## Summary
Protocol won't be eligible for referral rewards for depositing ETH, as the referral account is not properly set.

## Vulnerability Detail
When user sends ETH to contract **SophonFarming**, or calls ETH deposit functions, protocol will first deposit ETH on external protocols (Lido or Ether.fi) for minting staking shares, then warp the shares to the predefined assets (wstETH or weETH), then user  starts to earn reward points.

The external protocols allows caller to pass referral argument when depositing ETH, and referral account can be eligible for referral rewards if it is valid. Let's take Ether.fi for example:
```solidity
    function _ethTOeEth(uint256 _amount) internal returns (uint256) {
        // deposit returns exact amount of eETH
        return IeETHLiquidityPool(eETHLiquidityPool).deposit{value: _amount}(address(this));
    }
```

To convert ETH to eETH, the function `deposit` in [IeETHLiquidityPool](https://etherscan.io/address/0x605f17e88027e25e18c95be0d8011ac969426399#code) is called. In fact, **IeETHLiquidityPool** exposes 2 deposit functions for users to deposit ETH, which have different signatures:
```solidity
    // Used by eETH staking flow
    function deposit() external payable returns (uint256) {
        return deposit(address(0));
    }

    // Used by eETH staking flow
    function deposit(address _referral) public payable whenNotPaused returns (uint256) {
        require(_isWhitelisted(msg.sender), "Invalid User");

        emit Deposit(msg.sender, msg.value, SourceOfFunds.EETH, _referral);

        return _deposit(msg.sender, msg.value, 0);
    }
```
The `_referral` parameter in the second deposit function indicates the referral account which will be eligible for referral rewards, as stated by ether.fi [here](https://etherfi.gitbook.io/etherfi/getting-started/loyalty-points/referrals):
> This referral program covers both ether.fi and ether.fan, each 0.1 ETH staked via ether.fi or ether.fan earns the person who stakes > and the the person who referred 100 loyalty points.
>
> Note: Referral points may take up to 2 hours to display in your Portfolio.

Apparently, by calling the second deposit function and passing **address(this)** as `_referral` argument, our protocol expects to receive the referral rewards, however, this makes the referral as the same account as the depositor itself (msg.sender), this is invalid to ether.fi and no rewards will be granted to the account which uses one's own referral code for depositing.

Similarly, protocol won't receive referral rewards from Lido as it set referral to itself when submit to deposit ETH:
```solidity
    function _ethTOstEth(uint256 _amount) internal returns (uint256) {
        // submit function does not return exact amount of stETH so we need to check balances
        uint256 balanceBefore = IERC20(stETH).balanceOf(address(this));
@=>     IstETH(stETH).submit{value: _amount}(address(this));
        return (IERC20(stETH).balanceOf(address(this)) - balanceBefore);
    }
```

## Impact
Protocol won't be eligible for referral rewards as expected, this can be significant value leak to the protocol.

## Code Snippet
https://github.com/sherlock-audit/2024-05-sophon/blob/main/farming-contracts/contracts/farm/SophonFarming.sol#L811
https://github.com/sherlock-audit/2024-05-sophon/blob/main/farming-contracts/contracts/farm/SophonFarming.sol#L834

## Tool used
Manual Review

## Recommendation
User `owner` account as referral instead of the caller contract itself.
```diff
    function _ethTOstEth(uint256 _amount) internal returns (uint256) {
        // submit function does not return exact amount of stETH so we need to check balances
        uint256 balanceBefore = IERC20(stETH).balanceOf(address(this));
-       IstETH(stETH).submit{value: _amount}(address(this));
+       IstETH(stETH).submit{value: _amount}(owner());
        return (IERC20(stETH).balanceOf(address(this)) - balanceBefore);
    }
```

```diff
    function _ethTOeEth(uint256 _amount) internal returns (uint256) {
        // deposit returns exact amount of eETH
-       return IeETHLiquidityPool(eETHLiquidityPool).deposit{value: _amount}(address(this));
+       return IeETHLiquidityPool(eETHLiquidityPool).deposit{value: _amount}(owner());
    }
```
