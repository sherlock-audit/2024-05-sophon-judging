# Issue H-1: Many cases `stEth::transferFrom` will transfer 1-2 less way, which would result in revert in consequent functions, because of not enough balance 

Source: https://github.com/sherlock-audit/2024-05-sophon-judging/issues/63 

## Found by 
Bauchibred, EgisSecurity, zzykxx
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



## Discussion

**sherlock-admin4**

1 comment(s) were left on this issue during the judging contest.

**0xmystery** commented:
>  valid because this parallels FOT as documented by Lido (best because the report is succinct and well documented)



# Issue M-1: The quantity is calculated incorrectly when depositing ETH to weETH. 

Source: https://github.com/sherlock-audit/2024-05-sophon-judging/issues/4 

## Found by 
EgisSecurity, hunter\_w3b, p0wd3r, zzykxx
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



## Discussion

**sherlock-admin4**

1 comment(s) were left on this issue during the judging contest.

**0xmystery** commented:
>  valid because it's the shares that matter (best because report is most succint)



# Issue M-2: Protocol won't be eligible for referral rewards for depositing ETH 

Source: https://github.com/sherlock-audit/2024-05-sophon-judging/issues/92 

## Found by 
h2134
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



## Discussion

**sherlock-admin3**

1 comment(s) were left on this issue during the judging contest.

**0xmystery** commented:
>  valid because referral should indeed be an EOA which can be multisig 



# Issue M-3: `setStartBlock()` doesn't change the block at which already existing pools will start accumulating points 

Source: https://github.com/sherlock-audit/2024-05-sophon-judging/issues/108 

## Found by 
0xAadi, EgisSecurity, KupiaSec, MightyRaju, ZdravkoHr., araj, blackhole, dhank, h2134, jecikpo, serial-coder, underdog, utsav, whitehair0330, yamato, zzykxx
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



## Discussion

**sherlock-admin4**

1 comment(s) were left on this issue during the judging contest.

**0xmystery** commented:
>  valid because lastRewardBlock for each pool should indeed sync with the latest startBlock (best because the report is succinct and comprehensive explaining each of the two scenarios)



# Issue M-4: SophonFarming.sol 

Source: https://github.com/sherlock-audit/2024-05-sophon-judging/issues/195 

## Found by 
EgisSecurity, aslanbek
## Summary
SophonFarming.sol - If a pool doesn't have any deposits, after it has started, it will eat up the allocation of points of other pools

## Vulnerability Detail

The protocol implements a system of allocation points, which basically dictate how much `pointsPerBlock` each pool has to receive each block, based on the `totalAllocPoints`.

```solidity
function updatePool(uint256 _pid) public {
        PoolInfo storage pool = poolInfo[_pid];
        if (getBlockNumber() <= pool.lastRewardBlock) {
            return;
        }
        uint256 lpSupply = pool.amount;
        uint256 _pointsPerBlock = pointsPerBlock;
        uint256 _allocPoint = pool.allocPoint;
        if (lpSupply == 0 || _pointsPerBlock == 0 || _allocPoint == 0) {
            pool.lastRewardBlock = getBlockNumber();
            return;
        }
        uint256 blockMultiplier = _getBlockMultiplier(pool.lastRewardBlock, getBlockNumber());
        
        uint256 pointReward =
            blockMultiplier *
            _pointsPerBlock *
            _allocPoint /
            totalAllocPoint;

        pool.accPointsPerShare = pointReward /
            lpSupply +
            pool.accPointsPerShare;

        pool.lastRewardBlock = getBlockNumber();
    }
```

The `pool.allocPoints` represents said allocation points per pool, which are used to calculate the `pointReward` when `updatePool` is called. The pool only starts accruing points, after `lpSupply != 0`, if `pool.allocPoints == 0` the the pool is "disabled" and so it doesn't affect other pools.

The issue here is the fact that, `totalAllocPoints` represent how much are the total `pool.allocPoints` of each pool, but it doesn't account for the fact, that the pool might not have depositors in it yet.

Let's imagine the following:
1. We have 2 pools and their allocation points are 50/50, while `pointsPerBlock = 10`, meaning that every block each pool has to accumulate a total of 5 points.
2. Before the pool has started, someone deposits in the first pool, but no one has still deposited in the second pool.
3. 10 block pass and now all the pools must have accrued a total of 100 points, but only pool 1 has accrued any points, it has accrued it's 50.
4. Because the `pool.amount = 0` for pool 2, `updatePool` doesn't do anything as even if it's called, we will go into this if statement and just set `lastRewardBlock = block.number`.
```solidity
if (lpSupply == 0 || _pointsPerBlock == 0 || _allocPoint == 0) {
            pool.lastRewardBlock = getBlockNumber();
            return;
        }
```
5. Whenever someone deposits into pool 2, that's when it will start accruing points, thus after said block, all `pointsPerBlock` will start accruing, not just 50% of them as in the example.

Active pools are punished for the inactive/empty pools and accrue less points because of it.

Note that the variable explicitly states:
```jsx
    // Points created per block.
    uint256 public pointsPerBlock;
```

Because of this issue, not all points are created per block.

## Impact
Not all `pointsPerBlock` will be accrued per each block.

## Code Snippet
https://github.com/sherlock-audit/2024-05-sophon/blob/main/farming-contracts/contracts/farm/SophonFarming.sol#L419-L422

## Tool used
Manual Review

## Recommendation
If there are any inactive pools, don't take them into account when calculating the `pointReward` for active pools.



## Discussion

**sherlock-admin4**

1 comment(s) were left on this issue during the judging contest.

**0xmystery** commented:
>  valid because only active pools should be included in totalAllocPoints (best because of more detailed POC)



**RomanHiden**

the issue description doesn't match the issue a little bit. if a pool is inactive its allocation points will not be rewarded. 

```
We have 2 pools and their allocation points are 50/50, while pointsPerBlock = 10, meaning that every block each pool has to accumulate a total of 5 points.
Before the pool has started, someone deposits in the first pool, but no one has still deposited in the second pool.
10 block pass and now all the pools must have accrued a total of 100 points, but only pool 1 has accrued any points, it has accrued it's 50.
```

pool 1 is entitled to 5 points per block. and it gets in the end 5 points per block 10 blocks = 50. pool 1 earnings doesn't depend on pool1 being active or not. it will always get 50 points 

**mystery0x**

The report is trying the stress that pool 1 should justifiably get 100 points instead of 50 points for the first 10 blocks when pool 2 is empty. The denominator, `totalAllocPoint` , could have been been 50 instead of 100.

**RomanHiden**

That's not our intended design. Pool1 should get 50 points 

**mystery0x**

If a fix was made as suggested, this would help mitigate existing issues when `_withUpdate` was accidentally inputted false in add() and set().

