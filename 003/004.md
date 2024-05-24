Zesty Amber Swan

high

# The quantity is calculated incorrectly when depositing ETH to weETH.

## Summary
The quantity is calculated incorrectly when depositing ETH to weETH.

The code treats **the quantity of eETH shares** returned by Etherfi `LiquidityPool.deposit` as **the actual quantity of eETH**, but these two quantities are not equal.

The Etherfi `LiquidityPool.deposit` and `stETH.submit` functions have the same behavior, both returning shares instead of the actual token amount. The protocol handles stETH correctly, but it doesn't handle eETH correctly.
## Vulnerability Detail
In `depositEth`, if `_predefinedPool == PredefinedPool.weETH`, `_ethTOeEth` will be called to get the `finalAmount`.

https://github.com/sherlock-audit/2024-05-sophon/blob/main/farming-contracts/contracts/farm/SophonFarming.sol#L503-L516
```solidity
    function depositEth(uint256 _boostAmount, PredefinedPool _predefinedPool) public payable {
        if (msg.value == 0) {
            revert NoEthSent();
        }

        uint256 _finalAmount = msg.value;
        if (_predefinedPool == PredefinedPool.wstETH) {
            _finalAmount = _ethTOstEth(_finalAmount);
        } else if (_predefinedPool == PredefinedPool.weETH) {
            _finalAmount = _ethTOeEth(_finalAmount);
        }

        _depositPredefinedAsset(_finalAmount, msg.value, _boostAmount, _predefinedPool);
    }
```

`_ethTOeEth` will call Etherfi `LiquidityPool.deposit`.

https://github.com/sherlock-audit/2024-05-sophon/blob/main/farming-contracts/contracts/farm/SophonFarming.sol#L832-L835
```solidity
    function _ethTOeEth(uint256 _amount) internal returns (uint256) {
        // deposit returns exact amount of eETH
        return IeETHLiquidityPool(eETHLiquidityPool).deposit{value: _amount}(address(this));
    }
```

The comment in `_ethTOeEth` states that the return value is the amount of eETH, but in reality Etherfi uses `mintShare` and returns the amount of shares.

https://github.com/etherfi-protocol/smart-contracts/blob/master/src/LiquidityPool.sol#L523-L533
```solidity
    function _deposit(address _recipient, uint256 _amountInLp, uint256 _amountOutOfLp) internal returns (uint256) {
        totalValueInLp += uint128(_amountInLp);
        totalValueOutOfLp += uint128(_amountOutOfLp);
        uint256 amount = _amountInLp + _amountOutOfLp;
        uint256 share = _sharesForDepositAmount(amount);
        if (amount > type(uint128).max || amount == 0 || share == 0) revert InvalidAmount();

        eETH.mintShares(_recipient, share);

        return share;
    }
```

`_depositPredefinedAsset` is called in `depositEth`, which in turn called `_eethTOweEth`, and the parameter is the share quantity of eETH returned by `_ethTOeEth`.

https://github.com/sherlock-audit/2024-05-sophon/blob/main/farming-contracts/contracts/farm/SophonFarming.sol#L556-L557
```solidity
        } else if (_predefinedPool == PredefinedPool.weETH) {
            _finalAmount = _eethTOweEth(_amount);
```

https://github.com/sherlock-audit/2024-05-sophon/blob/main/farming-contracts/contracts/farm/SophonFarming.sol#L843-L846
```solidity
    function _eethTOweEth(uint256 _amount) internal returns (uint256) {
        // wrap returns exact amount of weETH
        return IweETH(weETH).wrap(_amount);
    }
```

**However, in `weETH.wrap`, the parameter should be the actual amount of eETH rather than the amount of shares, as there is a conversion relationship between the actual amount and the amount of shares, they are not equal.**

https://github.com/etherfi-protocol/smart-contracts/blob/master/src/WeETH.sol#L49-L55
```solidity
    function wrap(uint256 _eETHAmount) public returns (uint256) {
        require(_eETHAmount > 0, "weETH: cant wrap zero eETH");
        uint256 weEthAmount = liquidityPool.sharesForAmount(_eETHAmount);
        _mint(msg.sender, weEthAmount);
        eETH.transferFrom(msg.sender, address(this), _eETHAmount); //@audit amount, not share
        return weEthAmount;
    }
```

`eETH.transferFrom` is to convert amount to share and then `transferShare`.

https://github.com/etherfi-protocol/smart-contracts/blob/master/src/EETH.sol#L111-L119
https://github.com/etherfi-protocol/smart-contracts/blob/master/src/EETH.sol#L143-L147
```solidity
    function _transfer(address _sender, address _recipient, uint256 _amount) internal {
        uint256 _sharesToTransfer = liquidityPool.sharesForAmount(_amount); //@audit convert amount to share
        _transferShares(_sender, _recipient, _sharesToTransfer);
        emit Transfer(_sender, _recipient, _amount);
    }
```

As for why the current test cases pass, it is because `MockEETHLiquidityPool.deposit` uses `eEth.mint(msg.sender, mintAmount);`, which directly increases the amount of eETH and returns that amount directly, rather than returning the number of shares as in Etherfi.

https://github.com/sherlock-audit/2024-05-sophon/blob/main/farming-contracts/contracts/mocks/MockeETHLiquidityPool.sol#L18-L26
```solidity
    function deposit(address _referral) external payable returns (uint256) {
        _referral;
        
        uint256 mintAmount = msg.value / 1001 * 1000;
        
        eEth.mint(msg.sender, mintAmount);

        return mintAmount;
    }
```
## Impact
As there is a conversion rate between the amount of eETH and the number of shares, which are not equal, the following situations may occur:
- If 100 ETH is deposited, 100 eETH and 90 eETH shares are obtained, then `weETH.wrap(90)` is executed, 10 eETH cannot be deposited into the pool, and the user loses assets.
- If 100 ETH is deposited, 100 eETH and 110 eETH shares are obtained, then `weETH.wrap(110)` is executed. Since there are only 100 eETH, the transaction will revert and the user will not be able to deposit assets.
## Code Snippet
- https://github.com/sherlock-audit/2024-05-sophon/blob/main/farming-contracts/contracts/farm/SophonFarming.sol#L503-L516
- https://github.com/sherlock-audit/2024-05-sophon/blob/main/farming-contracts/contracts/farm/SophonFarming.sol#L832-L835
- https://github.com/etherfi-protocol/smart-contracts/blob/master/src/LiquidityPool.sol#L523-L533
- https://github.com/sherlock-audit/2024-05-sophon/blob/main/farming-contracts/contracts/farm/SophonFarming.sol#L556-L557
- https://github.com/sherlock-audit/2024-05-sophon/blob/main/farming-contracts/contracts/farm/SophonFarming.sol#L843-L846
- https://github.com/etherfi-protocol/smart-contracts/blob/master/src/WeETH.sol#L49-L55
- https://github.com/etherfi-protocol/smart-contracts/blob/master/src/EETH.sol#L111-L119
- https://github.com/etherfi-protocol/smart-contracts/blob/master/src/EETH.sol#L143-L147
- https://github.com/sherlock-audit/2024-05-sophon/blob/main/farming-contracts/contracts/mocks/MockeETHLiquidityPool.sol#L18-L26
## Tool used
Manual Review

## Recommendation
Like `_ethTOstEth`, return the difference of eETH balance instead of directly returning the result of `LiquidityPool.deposit`.

https://github.com/sherlock-audit/2024-05-sophon/blob/main/farming-contracts/contracts/farm/SophonFarming.sol#L808-L813
```solidity
    function _ethTOstEth(uint256 _amount) internal returns (uint256) {
        // submit function does not return exact amount of stETH so we need to check balances
        uint256 balanceBefore = IERC20(stETH).balanceOf(address(this));
        IstETH(stETH).submit{value: _amount}(address(this));
        return (IERC20(stETH).balanceOf(address(this)) - balanceBefore);
    }
```