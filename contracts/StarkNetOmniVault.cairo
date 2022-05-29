%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.uint256 import Uint256, uint256_add, uint256_neg, uint256_le
from starkware.starknet.common.syscalls import get_contract_address, get_caller_address
from contracts.interfaces.IERC20 import IERC20

@storage_var
func _omni_vault_deposit(key : Uint256) -> (deposited : felt):
end

@external
func lock_funds_for_key{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    key : Uint256, token : felt, amount : Uint256
):
    alloc_locals
    let (_deposited) = _omni_vault_deposit.read(key)
    with_attr error_message("Vault key already deposited"):
        _deposited = 0
    end

    let (self) = get_contract_address()
    let (caller) = get_caller_address()

    let (pre_balance : Uint256) = IERC20.balanceOf(contract_address=token, account=self)
    IERC20.transferFrom(contract_address=token, sender=caller, recipient=self, amount=amount)
    let (post_balance : Uint256) = IERC20.balanceOf(contract_address=token, account=self)

    with_attr error_message("Insufficient deposit amount"):
        let (neg_pre_balance) = uint256_neg(pre_balance)
        let (deposit_amount, _) = uint256_add(post_balance, neg_pre_balance)
        let (is_sufficient_deposit_amount) = uint256_le(amount, deposit_amount)
        assert is_sufficient_deposit_amount = 1
    end

    _omni_vault_deposit.write(key=key, value=1)

    return ()
end
