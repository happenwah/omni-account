%lang starknet

from starkware.cairo.common.uint256 import Uint256

struct CallArray:
    member to : felt
    member selector : felt
    member data_offset : felt
    member data_len : felt
end

@contract_interface
namespace IOmniAccount:
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

    func change_eth_signer(new_eth_signer : felt):
    end

    func change_stark_signer(new_stark_signer : felt):
    end

    func is_valid_eth_signature(hash_low : felt, hash_high : felt, sig_len : felt, sig : felt*):
    end

    func is_valid_stark_signature(hash : felt, sig_len : felt, sig : felt*):
    end

    func get_nonce() -> (nonce : felt):
    end

    func get_eth_signer() -> (eth_signer : felt):
    end

    func get_stark_signer() -> (stark_signer : felt):
    end

    func get_version() -> (version : felt):
    end
end
