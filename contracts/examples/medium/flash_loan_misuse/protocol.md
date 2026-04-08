# Flash Loan Lending Pool

## Description
A lending pool that supports flash loans using the hot potato pattern.
Users can borrow SUI within a single transaction as long as they repay
the full amount before the transaction completes.

## Intended Behavior
- `provide_liquidity`: Anyone can deposit SUI to grow the pool.
- `borrow`: Borrow SUI and receive a receipt (hot potato). Must repay
  in the same transaction.
- `repay`: Return borrowed SUI and consume the receipt. Pool balance
  must be at least as large after repayment as before borrowing.

## Invariants
- The pool balance after a flash loan transaction must be >= the balance before.
- The borrower must return at least the borrowed amount from the loan itself.
- No user should be able to profit from a flash loan without an external
  arbitrage source — the pool itself should never lose funds.
