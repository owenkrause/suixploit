# Reward Pool

## Description
A staking pool where users deposit SUI and receive share tokens
proportional to their deposit. An admin can add reward tokens to the
pool, increasing the value of each share.

## Intended Behavior
- `deposit`: User deposits SUI, receives shares proportional to their
  contribution relative to the pool's total value.
- `withdraw`: User burns shares, receives proportional SUI back.
- `add_rewards`: Admin adds SUI rewards to increase share value for
  all depositors.

## Invariants
- A depositor should always receive shares proportional to their deposit.
- No depositor should be able to extract more value than they deposited
  plus their fair share of rewards.
- The pool should never lose funds except via legitimate withdrawals.
