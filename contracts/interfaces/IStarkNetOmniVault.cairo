%lang starknet

from starkware.cairo.common.uint256 import Uint256

@contract_interface
namespace IStarkNetOmniVault:
    func lock_funds_for_key(
        key : Uint256,
        token : felt,
        amount : Uint256,
        default_eth_signer : felt,
        fallback_recipient : felt,
        eth_signature_r : Uint256,
        eth_signature_s : Uint256,
        eth_signature_v : Uint256,
    ):
    end

    func unlock_funds_for_key(
        key : Uint256,
        eth_signature_r : Uint256,
        eth_signature_s : Uint256,
        eth_signature_v : Uint256,
    ):
    end
end
