%lang starknet

from starkware.cairo.common.uint256 import Uint256

@contract_interface
namespace IStarkNetOmniVault:
    func lock_funds_for_key(key : Uint256, token : felt, amount : Uint256) -> (success : felt):
    end

    func unlock_funds_for_key(
        key : Uint256, signature_r : Uint256, signature_s : Uint256, signature_v : felt
    ) -> (success : felt):
    end
end
