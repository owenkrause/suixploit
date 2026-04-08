# Auction

## Description
A shared-object auction where users place SUI bids. The highest bidder
wins when the auction is settled. Outbid users receive receipts to
claim refunds.

## Intended Behavior
- `create_auction`: Create a new auction with an end time.
- `bid`: Place a bid higher than the current highest. Previous high bidder
  gets a refund receipt.
- `settle`: After the end time, finalize the auction. Pay the seller the
  winning bid amount.
- `claim_refund`: Outbid users redeem their receipt for a refund.

## Invariants
- The auction can only be settled after the end time.
- The seller receives exactly the highest bid amount, no more.
- All outbid users can claim full refunds of their bid amounts.
- No funds should be lost or trapped in the contract.
