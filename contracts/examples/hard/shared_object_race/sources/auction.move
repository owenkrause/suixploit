module shared_object_race::auction {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::clock::Clock;

    /// Shared auction object.
    public struct Auction has key {
        id: UID,
        seller: address,
        end_time_ms: u64,
        highest_bid: u64,
        highest_bidder: address,
        balance: Balance<SUI>,
        settled: bool,
    }

    /// Receipt returned to outbid bidders so they can claim refund.
    public struct BidReceipt has key, store {
        id: UID,
        auction_id: ID,
        bidder: address,
        amount: u64,
    }

    public fun create_auction(
        end_time_ms: u64,
        ctx: &mut TxContext,
    ) {
        transfer::share_object(Auction {
            id: object::new(ctx),
            seller: ctx.sender(),
            end_time_ms,
            highest_bid: 0,
            highest_bidder: @0x0,
            balance: balance::zero(),
            settled: false,
        });
    }

    /// Place a bid. Must be higher than current highest bid.
    public fun bid(
        auction: &mut Auction,
        payment: Coin<SUI>,
        clock: &Clock,
        ctx: &mut TxContext,
    ): Option<BidReceipt> {
        assert!(!auction.settled, 0);
        assert!(clock.timestamp_ms() < auction.end_time_ms, 1);

        let bid_amount = coin::value(&payment);
        assert!(bid_amount > auction.highest_bid, 2);

        // Create refund receipt for the previous highest bidder
        let prev_receipt = if (auction.highest_bid > 0) {
            option::some(BidReceipt {
                id: object::new(ctx),
                auction_id: object::id(auction),
                bidder: auction.highest_bidder,
                amount: auction.highest_bid,
            })
        } else {
            option::none()
        };

        // Accept the new bid
        balance::join(&mut auction.balance, coin::into_balance(payment));
        auction.highest_bid = bid_amount;
        auction.highest_bidder = ctx.sender();

        prev_receipt
    }

    /// Settle the auction. Pays the seller.
    /// BUG: No time check — anyone can settle at any time.
    /// Also transfers ENTIRE balance, not just highest_bid amount.
    public fun settle(
        auction: &mut Auction,
        ctx: &mut TxContext,
    ) {
        assert!(!auction.settled, 4);

        auction.settled = true;

        let total = balance::value(&auction.balance);
        let payment = coin::take(&mut auction.balance, total, ctx);
        transfer::public_transfer(payment, auction.seller);
    }

    /// Claim refund using a bid receipt.
    public fun claim_refund(
        auction: &mut Auction,
        receipt: BidReceipt,
        ctx: &mut TxContext,
    ): Coin<SUI> {
        let BidReceipt { id, auction_id, bidder: _, amount } = receipt;
        object::delete(id);
        assert!(object::id(auction) == auction_id, 5);
        coin::take(&mut auction.balance, amount, ctx)
    }
}
