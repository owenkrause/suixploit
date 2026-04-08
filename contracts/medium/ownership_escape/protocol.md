# Marketplace

## Description
A peer-to-peer marketplace where users list items for sale. Buyers pay
SUI to purchase listed items. The marketplace takes a 2.5% fee.

## Intended Behavior
- `mint_item`: Create a new item (for testing purposes).
- `list_item`: Seller lists an item at a price. Item is held by the listing.
- `buy_item`: Buyer pays the listed price. Seller receives payment minus fee.
- `cancel_listing`: Only the original seller can cancel and reclaim their item.

## Invariants
- Only the seller who listed an item can cancel that listing.
- A buyer must pay at least the listed price to purchase an item.
- Items in active listings cannot be taken without paying or being the seller.
