%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin, BitwiseBuiltin
from starkware.cairo.common.signature import verify_ecdsa_signature
from starkware.cairo.common.cairo_keccak.keccak import keccak_uint256s
from starkware.cairo.common.cairo_secp.signature import verify_eth_signature_uint256
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.memcpy import memcpy
from starkware.cairo.common.math import assert_not_zero
from starkware.cairo.common.math_cmp import is_nn
from starkware.starknet.common.syscalls import (
    call_contract,
    get_tx_info,
    get_contract_address,
    get_caller_address,
    get_block_timestamp,
)

from contracts.utils.uint256_utils import felt_to_uint256
from contracts.interfaces.IERC20 import IERC20
from contracts.interfaces.IStarkNetOmniVault import IStarkNetOmniVault

####################
# CONSTANTS
####################

const VERSION = '0.1.0'

const TRUE = 1
const FALSE = 0

####################
# STRUCTS
####################

struct Call:
    member to : felt
    member selector : felt
    member calldata_len : felt
    member calldata : felt*
end

struct CallArray:
    member to : felt
    member selector : felt
    member data_offset : felt
    member data_len : felt
end

####################
# EVENTS
####################

@event
func eth_signer_changed(new_eth_signer : felt):
end

@event
func stark_signer_changed(new_stark_signer : felt):
end

@event
func account_upgraded(new_implementation : felt):
end

@event
func transaction_executed(hash : felt, response_len : felt, response : felt*):
end

####################
# STORAGE VARIABLES
####################

@storage_var
func _lock() -> (res : felt):
end

@storage_var
func _current_nonce() -> (res : felt):
end

@storage_var
func _eth_signer() -> (res : felt):
end

@storage_var
func _stark_signer() -> (res : felt):
end

@storage_var
func _starknet_omni_vault() -> (res : felt):
end

####################
# EXTERNAL FUNCTIONS
####################

@external
func initialize{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    eth_signer : felt, stark_signer : felt, starknet_omni_vault : felt
):
    # Check that we are not already initialized
    let (current_eth_signer) = _eth_signer.read()
    let (current_stark_signer) = _stark_signer.read()
    let (current_starknet_omni_vault) = _starknet_omni_vault.read()
    with_attr error_message("Already initialized"):
        assert current_eth_signer = 0
        assert current_stark_signer = 0
        assert current_starknet_omni_vault = 0
    end
    # Prevent null value
    with_attr error_message("Cannot be null"):
        assert_not_zero(eth_signer)
        assert_not_zero(stark_signer)
        assert_not_zero(starknet_omni_vault)
    end
    # Initialize the contract
    _eth_signer.write(eth_signer)
    _stark_signer.write(stark_signer)
    _starknet_omni_vault.write(starknet_omni_vault)
    return ()
end

# @notice Allows third-party (caller) to securely lock funds into StarkNetOmniVault for this account's owner.
#         Assumes that caller has approved this account to transfer funds into StarkNetOmniVault.
# @param origin_chain_id Origin chain id for account's owner.
# @param starknet_token Address of StarkNet ERC20 token to be locked.
# @param starknet_token_amount_minus_fee Amount that caller should lock into StarkNetOmniVault.
#         Assumes that account's owner locked starknet_token_amount on origin chain.
# @param to Address to execute external call. Can be 0 if not required.
# @param selector Function selector to be called on to.
# @param calldata Payload for to.
# @param eth_signature_r_low Low bits of secp256k1 R coordinate.
# @param eth_signature_r_high High bits of secp256k1 R coordinate.
# @param eth_signature_s_low Low bits of secp256k1 S coordinate.
# @param eth_signature_s_high High bits of secp256k1 S coordinate.
# @param eth_signature_v secp256k1 V coordinate.
# @param fallback_recipient Allows caller to specify an address that can claim funds after the timelock period.
@external
func deposit_funds_into_vault{
    syscall_ptr : felt*, range_check_ptr, bitwise_ptr : BitwiseBuiltin*, pedersen_ptr : HashBuiltin*
}(
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
) -> ():
    alloc_locals
    # Reentrancy guard
    let (lock) = _lock.read()

    with_attr error_message("Reentrancy lock"):
        assert lock = FALSE
    end

    _lock.write(value=TRUE)
    # Enforce external call
    let (self) = get_contract_address()
    let (caller) = get_caller_address()

    with_attr error_message("Cannot be called via execute"):
        assert_not_zero(caller - self)
    end
    # Convert all args into uint256,
    # knowing that all fields have been encoded and hashed like so on origin_chain
    let (_origin_chain_id) = felt_to_uint256(origin_chain_id)
    let (_starknet_token) = felt_to_uint256(starknet_token)
    let (_starknet_token_amount_minus_fee) = felt_to_uint256(starknet_token_amount_minus_fee)
    let (_to) = felt_to_uint256(to)
    let (_selector) = felt_to_uint256(selector)

    let (calldata_uint256 : Uint256*) = alloc()
    from_felt_array_to_uint256_array(calldata_len, calldata, calldata_uint256)

    let _eth_signature_r = Uint256(low=eth_signature_r_low, high=eth_signature_r_high)
    let _eth_signature_s = Uint256(low=eth_signature_s_low, high=eth_signature_s_high)
    # Keccak(calldata)
    let (keccak_ptr : felt*) = alloc()
    with keccak_ptr:
        let (calldata_hash) = keccak_uint256s(calldata_len, calldata_uint256)
    end

    let (hash_array : Uint256*) = alloc()
    assert [hash_array] = _origin_chain_id
    assert [hash_array + 1 * Uint256.SIZE] = _starknet_token
    assert [hash_array + 2 * Uint256.SIZE] = _starknet_token_amount_minus_fee
    assert [hash_array + 3 * Uint256.SIZE] = _to
    assert [hash_array + 4 * Uint256.SIZE] = _selector
    assert [hash_array + 5 * Uint256.SIZE] = calldata_hash
    # Compute digest
    with keccak_ptr:
        let (digest) = keccak_uint256s(6 * Uint256.SIZE, hash_array)
    end
    let (exec_call) = is_nn(to)
    if exec_call == TRUE:
        # Optimistically execute external call,
        # knowing that StarkNetOmniVault will verify eth signature
        call_contract(
            contract_address=to,
            function_selector=selector,
            calldata_size=calldata_len,
            calldata=calldata,
        )
        tempvar syscall_ptr = syscall_ptr
    else:
        tempvar syscall_ptr = syscall_ptr
    end
    # Pull token amount from caller
    IERC20.transferFrom(
        contract_address=starknet_token,
        sender=caller,
        recipient=self,
        amount=_starknet_token_amount_minus_fee,
    )
    # Approve StarkNetOmniVault
    let (starknet_omni_vault) = _starknet_omni_vault.read()
    IERC20.approve(
        contract_address=starknet_token,
        spender=starknet_omni_vault,
        amount=_starknet_token_amount_minus_fee,
    )
    # Verify eth signature + lock funds so that eth_signer can withdraw later on
    let (eth_signer) = _eth_signer.read()
    IStarkNetOmniVault.lock_funds_for_key(
        contract_address=starknet_omni_vault,
        key=digest,
        token=starknet_token,
        amount=_starknet_token_amount_minus_fee,
        default_eth_signer=eth_signer,
        fallback_recipient=fallback_recipient,
        eth_signature_r=_eth_signature_r,
        eth_signature_s=_eth_signature_s,
        eth_signature_v=eth_signature_v,
    )
    # Unlock Reentrancy guard
    _lock.write(value=FALSE)

    return ()
end

# @notice Allows anyone with the correct signature to claim StarkNetOmniVault funds to this account,
#          while timelock is still active.
# @param key Hash that represents deposit to be claimed
# @param eth_signature_r secp256k1 R coordinate.
# @param eth_signature_s secp256k1 S coordinate.
# @param eth_signature_v secp256k1 V coordinate.
@external
func claim_funds_from_vault{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    key : Uint256, eth_signature_r : Uint256, eth_signature_s : Uint256, eth_signature_v : felt
):
    let (starknet_omni_vault) = _starknet_omni_vault.read()
    IStarkNetOmniVault.unlock_funds_for_key(
        starknet_omni_vault, key, eth_signature_r, eth_signature_s, eth_signature_v
    )

    return ()
end

@external
@raw_output
func __execute__{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, ecdsa_ptr : SignatureBuiltin*, range_check_ptr
}(
    call_array_len : felt,
    call_array : CallArray*,
    calldata_len : felt,
    calldata : felt*,
    nonce : felt,
) -> (retdata_size : felt, retdata : felt*):
    alloc_locals

    let (calls : Call*) = alloc()
    from_call_array_to_call(call_array_len, call_array, calldata, calls)
    let calls_len = call_array_len

    validate_and_bump_nonce(nonce)

    let (tx_info) = get_tx_info()

    assert_no_self_call(tx_info.account_contract_address, calls_len, calls)

    validate_stark_signature(tx_info.transaction_hash, tx_info.signature_len, tx_info.signature)

    local ecdsa_ptr : SignatureBuiltin* = ecdsa_ptr
    local syscall_ptr : felt* = syscall_ptr
    local range_check_ptr = range_check_ptr
    local pedersen_ptr : HashBuiltin* = pedersen_ptr
    let (response : felt*) = alloc()
    let (response_len) = execute_list(calls_len, calls, response)

    transaction_executed.emit(
        hash=tx_info.transaction_hash, response_len=response_len, response=response
    )
    return (retdata_size=response_len, retdata=response)
end

@external
func change_eth_signer{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    new_eth_signer : felt
):
    # Only called via execute
    assert_only_self()

    # Change eth signer
    with_attr error_message("Eth signer cannot be null"):
        assert_not_zero(new_eth_signer)
    end
    _eth_signer.write(new_eth_signer)
    eth_signer_changed.emit(new_eth_signer=new_eth_signer)
    return ()
end

@external
func change_stark_signer{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    new_stark_signer : felt
):
    # Only called via execute
    assert_only_self()

    # Change signer
    with_attr error_message("Stark signer cannot be null"):
        assert_not_zero(new_stark_signer)
    end
    _stark_signer.write(new_stark_signer)
    stark_signer_changed.emit(new_stark_signer=new_stark_signer)
    return ()
end

####################
# VIEW FUNCTIONS
####################

@view
func is_valid_eth_signature{
    syscall_ptr : felt*, range_check_ptr, pedersen_ptr : HashBuiltin*, bitwise_ptr : BitwiseBuiltin*
}(hash_low : felt, hash_high : felt, sig_len : felt, sig : felt*) -> ():
    let hash : Uint256 = Uint256(low=hash_low, high=hash_high)
    with_attr error_message("Invalid signature array length"):
        assert sig_len = 5
    end

    let signature_r : Uint256 = Uint256(low=sig[0], high=sig[1])
    let signature_s : Uint256 = Uint256(low=sig[2], high=sig[3])

    with_attr error_message("Invalid eth signature"):
        let (keccak_ptr : felt*) = alloc()
        with keccak_ptr:
            validate_eth_signature(hash, signature_r, signature_s, sig[4])
        end
    end

    return ()
end

@view
func is_valid_stark_signature{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr, ecdsa_ptr : SignatureBuiltin*
}(hash : felt, sig_len : felt, sig : felt*) -> ():
    validate_stark_signature(hash, sig_len, sig)
    return ()
end

@view
func get_nonce{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (
    nonce : felt
):
    let (res) = _current_nonce.read()
    return (nonce=res)
end

@view
func get_eth_signer{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (
    eth_signer : felt
):
    let (res) = _eth_signer.read()
    return (eth_signer=res)
end

@view
func get_stark_signer{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (
    stark_signer : felt
):
    let (res) = _stark_signer.read()
    return (stark_signer=res)
end

@view
func get_version() -> (version : felt):
    return (version=VERSION)
end

####################
# INTERNAL FUNCTIONS
####################

func assert_only_self{syscall_ptr : felt*}() -> ():
    let (self) = get_contract_address()
    let (caller_address) = get_caller_address()
    with_attr error_message("must be called via execute"):
        assert self = caller_address
    end
    return ()
end

func assert_no_self_call(self : felt, calls_len : felt, calls : Call*):
    if calls_len == 0:
        return ()
    end
    assert_not_zero(calls[0].to - self)
    assert_no_self_call(self, calls_len - 1, calls + Call.SIZE)
    return ()
end

func validate_and_bump_nonce{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    message_nonce : felt
) -> ():
    let (current_nonce) = _current_nonce.read()
    with_attr error_message("Invalid nonce"):
        assert current_nonce = message_nonce
    end
    _current_nonce.write(current_nonce + 1)
    return ()
end

func validate_eth_signature{
    syscall_ptr : felt*,
    range_check_ptr,
    pedersen_ptr : HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*,
    keccak_ptr : felt*,
}(hash : Uint256, signature_r : Uint256, signature_s : Uint256, signature_v : felt) -> ():
    alloc_locals
    with_attr error_message("Eth signature invalid"):
        let (eth_signer) = _eth_signer.read()
        verify_eth_signature_uint256(
            msg_hash=hash, r=signature_r, s=signature_s, v=signature_v, eth_address=eth_signer
        )
    end
    return ()
end

func validate_stark_signature{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr, ecdsa_ptr : SignatureBuiltin*
}(hash : felt, signature_len : felt, signature : felt*) -> ():
    with_attr error_message("Stark signature invalid"):
        let (stark_signer) = _stark_signer.read()
        verify_ecdsa_signature(
            message=hash,
            public_key=stark_signer,
            signature_r=signature[0],
            signature_s=signature[1],
        )
    end
    return ()
end

# @notice Executes a list of contract calls recursively.
# @param calls_len The number of calls to execute
# @param calls A pointer to the first call to execute
# @param response The array of felt to pupulate with the returned data
# @return response_len The size of the returned data
func execute_list{syscall_ptr : felt*}(calls_len : felt, calls : Call*, response : felt*) -> (
    response_len : felt
):
    alloc_locals

    # if no more calls
    if calls_len == 0:
        return (0)
    end

    # do the current call
    let this_call : Call = [calls]
    let res = call_contract(
        contract_address=this_call.to,
        function_selector=this_call.selector,
        calldata_size=this_call.calldata_len,
        calldata=this_call.calldata,
    )
    # copy the result in response
    memcpy(response, res.retdata, res.retdata_size)
    # do the next calls recursively
    let (response_len) = execute_list(calls_len - 1, calls + Call.SIZE, response + res.retdata_size)
    return (response_len + res.retdata_size)
end

func from_call_array_to_call{syscall_ptr : felt*}(
    call_array_len : felt, call_array : CallArray*, calldata : felt*, calls : Call*
):
    # if no more calls
    if call_array_len == 0:
        return ()
    end

    # parse the current call
    assert [calls] = Call(
        to=[call_array].to,
        selector=[call_array].selector,
        calldata_len=[call_array].data_len,
        calldata=calldata + [call_array].data_offset
        )

    # parse the remaining calls recursively
    from_call_array_to_call(
        call_array_len - 1, call_array + CallArray.SIZE, calldata, calls + Call.SIZE
    )
    return ()
end

func from_felt_array_to_uint256_array{range_check_ptr}(
    calldata_len : felt, calldata : felt*, calldata_uint256 : Uint256*
) -> ():
    if calldata_len == 0:
        return ()
    end

    let (calldata_) = felt_to_uint256([calldata])
    assert [calldata_uint256] = calldata_

    from_felt_array_to_uint256_array(calldata_len - 1, calldata + 1, calldata_uint256 + 1)

    return ()
end
