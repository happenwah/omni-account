%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, BitwiseBuiltin
from starkware.cairo.common.math_cmp import is_nn
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.uint256 import Uint256, uint256_add, uint256_neg, uint256_le
from starkware.cairo.common.cairo_keccak.keccak import keccak_uint256s
from starkware.starknet.common.syscalls import (
    get_contract_address,
    get_caller_address,
    get_block_timestamp,
)
from starkware.cairo.common.cairo_secp.signature import verify_eth_signature_uint256

from contracts.utils.uint256_utils import felt_to_uint256
from contracts.interfaces.IERC20 import IERC20

####################
# CONSTANTS
####################

# Keccak("StarkNet Ecosystem")
const STARKNET_ECOSYSTEM_HASH = 309689450920295678721545444397245125347984070251552327295375900229755709900
# One day
const TIMELOCK_PERIOD = 86400

const FALSE = 0
const TRUE = 1

####################
# STRUCTS
####################

struct VaultDeposit:
    member deposited : felt
    member withdrawn : felt
    member token : felt
    member default_recipient : felt
    member default_eth_signer : felt
    member fallback_recipient : felt
    member amount : Uint256
    member timelock : felt
end

####################
# STORAGE VARIABLES
####################

@storage_var
func _lock() -> (res : felt):
end

@storage_var
func _omni_vault_deposit(key : Uint256) -> (res : VaultDeposit):
end

####################
# EVENTS
####################

@event
func omni_vault_deposit(key : Uint256):
end

@event
func omni_vault_withdrawal(
    key : Uint256,
    salt : felt,
    eth_signature_r : Uint256,
    eth_signature_s : Uint256,
    eth_signature_v : felt,
):
end

####################
# EXTERNAL METHODS
####################

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
@external
func lock_funds_for_key{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, bitwise_ptr : BitwiseBuiltin*, range_check_ptr
}(
    key : Uint256,
    token : felt,
    amount : Uint256,
    default_eth_signer : felt,
    fallback_recipient : felt,
    eth_signature_r : Uint256,
    eth_signature_s : Uint256,
    eth_signature_v : felt,
):
    alloc_locals
    # Reentrancy guard
    let (lock) = _lock.read()

    with_attr error_message("Reentrancy lock"):
        assert lock = FALSE
    end

    let (vault_deposit) = _omni_vault_deposit.read(key=key)
    with_attr error_message("Vault key already deposited"):
        vault_deposit.deposited = FALSE
    end

    with_attr error_message("Vault key already withdrawn"):
        vault_deposit.withdrawn = FALSE
    end

    let (self) = get_contract_address()
    let (caller) = get_caller_address()

    with_attr error_message("Invalid eth signature"):
        let keccak_ptr : felt* = alloc()
        with keccak_ptr:
            verify_eth_signature_uint256(
                msg_hash=key,
                r=eth_signature_r,
                s=eth_signature_s,
                v=eth_signature_v,
                eth_address=default_eth_signer,
            )
        end
    end
    # Pull funds from caller
    let (pre_balance : Uint256) = IERC20.balanceOf(contract_address=token, account=self)
    IERC20.transferFrom(contract_address=token, sender=caller, recipient=self, amount=amount)
    let (post_balance : Uint256) = IERC20.balanceOf(contract_address=token, account=self)

    with_attr error_message("Insufficient deposit amount"):
        let (neg_pre_balance) = uint256_neg(pre_balance)
        let (deposit_amount, _) = uint256_add(post_balance, neg_pre_balance)
        let (is_sufficient_deposit_amount) = uint256_le(amount, deposit_amount)
        assert is_sufficient_deposit_amount = TRUE
    end
    # Register deposit
    let (block_timestamp) = get_block_timestamp()
    let _vault_deposit_value = VaultDeposit(
        deposited=TRUE,
        withdrawn=FALSE,
        token=token,
        default_recipient=caller,
        default_eth_signer=default_eth_signer,
        fallback_recipient=fallback_recipient,
        amount=deposit_amount,
        timelock=block_timestamp + TIMELOCK_PERIOD,
    )
    _omni_vault_deposit.write(key=key, value=_vault_deposit_value)

    omni_vault_deposit.emit(key=key)

    # Unlock Reentrancy guard
    _lock.write(value=FALSE)

    return ()
end

# @notice Allows caller to claim locked funds from `key`, by providing a signature for keccak([key, STARKNET_ECOSYSTEM_HASH].
#         In case timelock has expired, funds will instead go to `fallback_recipient`.
# @param key Hash (digest) that identifies the deposit.
# @param eth_signature_r secp256k1 R coordinate.
# @param eth_signature_s secp256k1 S coordinate.
# @param eth_signature_v secp256k1 V coordinate.
@external
func unlock_funds_for_key{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, bitwise_ptr : BitwiseBuiltin*, range_check_ptr
}(key : Uint256, eth_signature_r : Uint256, eth_signature_s : Uint256, eth_signature_v : felt):
    alloc_locals
    # Reentrancy guard
    let (lock) = _lock.read()

    with_attr error_message("Reentrancy lock"):
        assert lock = FALSE
    end

    let (vault_deposit) = _omni_vault_deposit.read(key)
    with_attr error_message("Vault key not deposited"):
        vault_deposit.deposited = TRUE
    end

    with_attr error_message("Vault key already withdrawn"):
        vault_deposit.withdrawn = FALSE
    end

    let (block_timestamp) = get_block_timestamp()
    let (has_lock_expired) = is_nn(block_timestamp - vault_deposit.timelock)

    if has_lock_expired == 0:
        # Compute keccak([key, STARKNET_ECOSYSTEM_HASH])
        let (hash_array : Uint256*) = alloc()
        assert [hash_array] = key
        let (starknet_ecosystem_hash) = felt_to_uint256(STARKNET_ECOSYSTEM_HASH)
        assert [hash_array + Uint256.SIZE] = starknet_ecosystem_hash
        # Verify eth signature
        with_attr error_message("Invalid eth signature"):
            let keccak_ptr : felt* = alloc()
            with keccak_ptr:
                let (digest) = keccak_uint256s(2 * Uint256.SIZE, hash_array)
                verify_eth_signature_uint256(
                    msg_hash=digest,
                    r=eth_signature_r,
                    s=eth_signature_s,
                    v=eth_signature_v,
                    eth_address=vault_deposit.default_eth_signer,
                )
            end
        end
        # Transfer funds to the intended recipient on StarkNet
        IERC20.transfer(
            contract_address=vault_deposit.token,
            recipient=vault_deposit.default_recipient,
            amount=vault_deposit.amount,
        )
        # Emit signature so that fallback_recipient can claim funds on origin EVM chain
        omni_vault_withdrawal.emit(
            key=key,
            salt=STARKNET_ECOSYSTEM_HASH,
            eth_signature_r=eth_signature_r,
            eth_signature_s=eth_signature_s,
            eth_signature_v=eth_signature_v,
        )
        tempvar bitwise_ptr = bitwise_ptr
        tempvar syscall_ptr = syscall_ptr
        tempvar range_check_ptr = range_check_ptr
    else:
        # After timelock expires we send funds to fallback_recipient,
        # since default_recipient did not claim funds on time.
        # It should now be possible for default_recipient to withdraw
        # his/her funds on origin chain.
        IERC20.transfer(
            contract_address=vault_deposit.token,
            recipient=vault_deposit.fallback_recipient,
            amount=vault_deposit.amount,
        )
        tempvar bitwise_ptr = bitwise_ptr
        tempvar syscall_ptr = syscall_ptr
        tempvar range_check_ptr = range_check_ptr
    end
    # Clear vault deposit
    let empty_vault_value = VaultDeposit(
        deposited=TRUE,
        withdrawn=TRUE,
        token=0,
        default_recipient=0,
        default_eth_signer=0,
        fallback_recipient=0,
        amount=Uint256(low=0, high=0),
        timelock=0,
    )
    _omni_vault_deposit.write(key=key, value=empty_vault_value)
    # Unlock Reentrancy guard
    _lock.write(value=FALSE)

    return ()
end
