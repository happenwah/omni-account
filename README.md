# StarkNet Omni Account

Cairo contracts that implement the Omni Account standard.

Omni accounts are owned by at least two private keys: 
- STARK key, used to natively sign StarkNet transactions.
- Ethereum key, which also belongs to the account owner and is typically used to sign transactions on EVM chains.

While solely transacting on StarkNet, Omni accounts are no different than any conventional StarkNet account: Interaction with other accounts is governed by STARK signatures.
But in cases where the account owner wants to send messages and funds from any EVM chain to StarkNet, it exposes two useful external methods: 

```cairo
# @notice Allows caller to lock funds that can be withdrawn later on by providing a new eth signature.
#         If timelock expires, anyone will be able to unlock funds to fallback_recipient address.
# @param key Hash (digest) that identifies this deposit.
# @param token Starknet address of ERC20 token to be deposited.
# @param amount Amount of token to be locked.
# @param default_eth_signer ETH address that has signed key.
# @param fallback_recipient Account that will receive funds in case timelock expires.
# @param eth_signature_r secp256k1 R coordinate.
# @param eth_signature_s secp256k1 S coordinate.
# @param eth_signature_v secp256k1 V coordinate.
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

- `deposit_funds_into_vault`: Can be called by an external account (counter-party) in order to safely deposit funds into a vault (`StarkNetOmniVault`). Integrity of data is ensured by the ECDSA signature provided by the account's owner, whose digest is `vault_key`. It is assumed that the account owner has already locked `starknet_token_amount` worth of `token` on the origin EVM chain, so that the counter-party is incentivized to lock said amount minus a fee that has been agreed upon.

- `claim_funds_from_vault`: Can be called by account's owner in order to claim the funds deposited in `StarkNetOmniVault`. In order to do so, a new signature must be provided: Signature of `keccak([vault_key, keccak("StarkNet Ecosystem")])`. Once this transaction is successful, account owner will get the funds into his/her account, and the emitted signature can be used for the counter-party to unlock funds on the origin EVM chain.

## Motivation

StarkNet's account abstraction unlocks plenty of novel use cases that have been made impossible under Ethereum EOAs, or at least very difficult to adopt due to high friction due to most users not wanting to actively manage smart contract wallets. This is an attempt to allow said accounts to be safely controlled by external EOA keys while allowing counter-parties to securely send messages and funds on the owners behalf. The underlying signature exchange protocol is heavily inspired by Connext's. Moreover, one could make an OmniAccount upgradeable and provide an UI to the user that allows him/her to customize it with all kinds of standards, of which this design could be a building block primitive.

## Assumptions

In order for this standard to work, there are assumptions on the liveness of both the account's owner and counter-party. The protocol works as described above as long as both parties lock and claim their share of funds under a `TIMELOCK_PERIOD` (currently set to 24h, but can be customized). Once timelock expires and the parties haven't completed their due transactions, they can always withdraw their share of funds: account owner withdraws `token_amount` on origin EVM chain and counter-party unlocks `token_amount_minus_fee` from the vault by sending it to a pre-specified `fallback_recipient`. 

While the modularily of this standard is attractive due to being a building block for accounts that allows two parties to permissionlessly exchange funds in a trust minimized manner, it would be more reliable and efficient for counter-parties to aggregate each other's bids in the origin EVM chain smart contract and allows users to choose. Any rogue counter-parties could be blacklisted by users, and risk losing their reputation over time. On the other hand, counter-parties with high uptime will earn more fees and earn on-chain reputation. This could be useful as a faster way to bridge funds from an EVM chain to StarkNet once two parties agree on the exchange, which could bypass the delay and caps of today's bridges.
