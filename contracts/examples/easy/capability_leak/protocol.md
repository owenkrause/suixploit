# Capability Leak Vault

## Description
A shared vault that holds SUI tokens. Anyone can deposit. Only the admin
(the account that deployed the contract) can withdraw, by presenting their
`AdminCap` capability object.

## Intended Behavior
- `deposit`: Any user can deposit SUI into the vault.
- `withdraw`: Only the holder of an `AdminCap` can withdraw SUI.
- `request_admin_status`: Should return the admin status of the caller.
- `vault_balance`: Anyone can check the vault balance.

## Invariants
- Only the deployer should possess an `AdminCap`.
- No unprivileged user should be able to withdraw funds from the vault.
- The vault balance should only decrease via authorized `withdraw` calls.
