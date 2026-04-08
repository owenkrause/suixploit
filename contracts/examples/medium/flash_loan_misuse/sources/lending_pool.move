module flash_loan_misuse::lending_pool {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;

    /// The lending pool holding SUI.
    public struct LendingPool has key {
        id: UID,
        balance: Balance<SUI>,
    }

    /// Hot potato — must be consumed by `repay` in the same transaction.
    /// Cannot be stored, copied, or dropped.
    public struct FlashLoanReceipt {
        pool_id: ID,
        borrow_amount: u64,
    }

    fun init(ctx: &mut TxContext) {
        transfer::share_object(LendingPool {
            id: object::new(ctx),
            balance: balance::zero(),
        });
    }

    /// Deposit SUI into the pool (liquidity provision).
    public fun provide_liquidity(
        pool: &mut LendingPool,
        coin: Coin<SUI>,
    ) {
        balance::join(&mut pool.balance, coin::into_balance(coin));
    }

    /// Borrow SUI via flash loan. Returns borrowed coin + receipt.
    /// Receipt MUST be consumed by `repay` in the same transaction.
    public fun borrow(
        pool: &mut LendingPool,
        amount: u64,
        ctx: &mut TxContext,
    ): (Coin<SUI>, FlashLoanReceipt) {
        assert!(balance::value(&pool.balance) >= amount, 0);

        let coin = coin::take(&mut pool.balance, amount, ctx);
        let receipt = FlashLoanReceipt {
            pool_id: object::id(pool),
            borrow_amount: amount,
        };

        (coin, receipt)
    }

    /// Repay a flash loan. Consumes the receipt (hot potato).
    /// BUG: Only checks value, not that pool balance is restored.
    /// An attacker who borrows X and already has Y >= X in SUI
    /// can repay with their existing Y, keeping the borrowed X.
    public fun repay(
        pool: &mut LendingPool,
        receipt: FlashLoanReceipt,
        repayment: Coin<SUI>,
    ) {
        let FlashLoanReceipt { pool_id, borrow_amount } = receipt;
        assert!(object::id(pool) == pool_id, 1);
        assert!(coin::value(&repayment) >= borrow_amount, 2);
        balance::join(&mut pool.balance, coin::into_balance(repayment));
    }

    public fun pool_balance(pool: &LendingPool): u64 {
        balance::value(&pool.balance)
    }
}
