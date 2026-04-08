module unchecked_arithmetic::reward_pool {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;

    /// A pool that accepts deposits and issues shares.
    /// Rewards are added separately by the admin, increasing
    /// the value of each share.
    public struct RewardPool has key {
        id: UID,
        balance: Balance<SUI>,
        total_shares: u64,
    }

    /// Represents a depositor's share of the pool.
    public struct ShareToken has key, store {
        id: UID,
        shares: u64,
    }

    /// Admin capability for adding rewards.
    public struct PoolAdmin has key, store {
        id: UID,
    }

    fun init(ctx: &mut TxContext) {
        transfer::transfer(
            PoolAdmin { id: object::new(ctx) },
            ctx.sender(),
        );
        transfer::share_object(RewardPool {
            id: object::new(ctx),
            balance: balance::zero(),
            total_shares: 0,
        });
    }

    /// Deposit SUI and receive proportional shares.
    public fun deposit(
        pool: &mut RewardPool,
        coin: Coin<SUI>,
        ctx: &mut TxContext,
    ): ShareToken {
        let amount = coin::value(&coin);

        let shares = if (pool.total_shares == 0) {
            amount
        } else {
            // BUG: Integer division truncates. If an attacker inflates the
            // share price via add_rewards before other users deposit,
            // new depositors can receive 0 shares while their SUI is
            // still added to the pool. Classic share-inflation / donation attack.
            (amount * pool.total_shares) / balance::value(&pool.balance)
        };

        balance::join(&mut pool.balance, coin::into_balance(coin));
        pool.total_shares = pool.total_shares + shares;

        ShareToken { id: object::new(ctx), shares }
    }

    /// Burn shares and withdraw proportional SUI.
    public fun withdraw(
        pool: &mut RewardPool,
        token: ShareToken,
        ctx: &mut TxContext,
    ): Coin<SUI> {
        let ShareToken { id, shares } = token;
        object::delete(id);

        let amount = (shares * balance::value(&pool.balance)) / pool.total_shares;
        pool.total_shares = pool.total_shares - shares;

        coin::take(&mut pool.balance, amount, ctx)
    }

    /// Admin adds rewards to the pool. Increases value of existing shares.
    /// BUG: Any AdminCap holder can call this, and it does not mint new
    /// shares — so if a single shareholder calls this, they capture
    /// 100% of the added rewards AND can use the inflated share price
    /// to steal from future depositors via truncation.
    public fun add_rewards(
        _admin: &PoolAdmin,
        pool: &mut RewardPool,
        coin: Coin<SUI>,
    ) {
        balance::join(&mut pool.balance, coin::into_balance(coin));
    }

    public fun pool_balance(pool: &RewardPool): u64 {
        balance::value(&pool.balance)
    }

    public fun pool_shares(pool: &RewardPool): u64 {
        pool.total_shares
    }

    public fun share_value(token: &ShareToken): u64 {
        token.shares
    }
}
