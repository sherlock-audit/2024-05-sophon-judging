Joyful Wintergreen Alligator

medium

# SophonFarming.sol - If a pool doesn't have any deposits, after it has started, it will eat up the allocation of points of other pools

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
