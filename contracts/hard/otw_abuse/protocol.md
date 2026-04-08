# Token (OTW Pattern)

## Description
A fungible token created using Sui's one-time witness pattern. The OTW
ensures that `create_currency` can only be called once during module
publication. A TreasuryCapHolder is shared to allow authorized minting.

## Intended Behavior
- `init`: Creates the TOKEN currency using the OTW, freezes metadata,
  shares the treasury cap holder.
- `mint`: Only authorized admins can mint new tokens.
- `burn`: Token holders can burn their tokens.

## Invariants
- Only authorized accounts should be able to mint new tokens.
- The OTW pattern must prevent creation of a second currency.
- Total supply should only increase via authorized mints.
- No unprivileged user should be able to inflate the token supply.
