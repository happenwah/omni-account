# StarkNet Omni Account

Cairo contracts that implement the Omni Account standard.

Omni accounts are owned by at least two private keys: 
- STARK key, used to natively sign StarkNet transactions.
- Ethereum key, which also belongs to the account owner and is typically used to sign transactions on EVM chains.

While solely transacting on StarkNet, Omni accounts are no different than any conventional StarkNet account. 
But in cases where the account owner wants to send messages and funds from any EVM chain to StarkNet, it exposes two useful external methods: 

```cairo
func deposit_funds_into_vault(
        origin_chain_id : felt,
        starknet_token : felt,
        starknet_token_amount_minus_fee : felt,
        to : felt,
        selector : felt,
        calldata_len : felt,
        calldata : felt*,
        eth_signature_r_low : felt,
        eth_signature_r_high : felt,
        eth_signature_s_low : felt,
        eth_signature_s_high : felt,
        eth_signature_v : felt,
        fallback_recipient : felt,
    ):
end

func claim_funds_from_vault(
    key_low : felt,
    key_high : felt,
    eth_signature_r_low : felt,
    eth_signature_r_high : felt,
    eth_signature_s_low : felt,
    eth_signature_s_high : felt,
    eth_signature_v : felt,
):
end
```

- `deposit_funds_into_vault`: Can be called by an external account (counter-party) in order to safely deposit funds into a vault (`StarkNetOmniVault`). Integrity of data is ensure by the ECDSA signature provided by the account's owner. It is assumed that the account owner has already locked `starknet_token_amount` worth of `token` on the origin EVM chain, so that the counter-party is incentivized to lock said amount minus a fee that has been agreed upon.

- `claim_funds_from_vault`: Can be called by account's owner in order to claim the funds deposited in `StarkNetOmniVault`. In order to do so, a new signature must be provided: Signature of `keccak([vault_key, keccak("StarkNet Ecosystem")])`, where `vault_key` is the digest from the previous deposit via `deposit_funds_into_vault`. Once this transaction is successful, account owner will get the funds into the account, and the emitted signature can be used for the counter-party to unlock funds on the origin EVM chain.
