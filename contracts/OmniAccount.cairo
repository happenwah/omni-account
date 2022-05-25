%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin, BitwiseBuiltin
from starkware.cairo.common.signature import verify_ecdsa_signature
from starkware.cairo.common.cairo_keccak.keccak import finalize_keccak, keccak_add_uint256
from starkware.cairo.common.cairo_secp.signature import verify_eth_signature_uint256
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.memcpy import memcpy
from starkware.cairo.common.math import assert_not_zero, assert_le, assert_nn
from starkware.starknet.common.syscalls import (
    call_contract,
    get_tx_info,
    get_contract_address,
    get_caller_address,
    get_block_timestamp,
)
from contracts.utils.uint256_utils import felt_to_uint256

@contract_interface
namespace IAccount:
    func supportsInterface(interfaceId : felt) -> (success : felt):
    end
end

####################
# CONSTANTS
####################

const VERSION = '0.1.0'

const ERC165_ACCOUNT_INTERFACE = 0xf10dbd44

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

# Tmp struct introduced while we wait for Cairo
# to support passing `[Call]` to __execute__
struct CallArray:
    member to : felt
    member selector : felt
    member data_offset : felt
    member data_len : felt
end

struct EVMCrossChainMessage:
    member origin_chain_id : felt
    member token : felt
    member token_amount_low : felt
    member token_amount_high : felt
    member signature_r_low : felt
    member signature_r_high : felt
    member signature_s_low : felt
    member signature_s_high : felt
    member signature_v : felt
    member to : felt
    member selector : felt
    member calldata_len : felt
    member calldata : felt*
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
func _current_nonce() -> (res : felt):
end

@storage_var
func _eth_signer() -> (res : felt):
end

@storage_var
func _stark_signer() -> (res : felt):
end

####################
# EXTERNAL FUNCTIONS
####################

@external
func initialize{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    eth_signer : felt, stark_signer
):
    # check that we are not already initialized
    let (current_eth_signer) = _eth_signer.read()
    let (current_stark_signer) = _stark_signer.read()
    with_attr error_message("already initialized"):
        assert current_eth_signer = 0
        assert current_stark_signer = 0
    end
    # check that the target signer is not zero
    with_attr error_message("signer cannot be null"):
        assert_not_zero(eth_signer)
        assert_not_zero(stark_signer)
    end
    # initialize the contract
    _eth_signer.write(eth_signer)
    _stark_signer.write(stark_signer)
    return ()
end

@external
func lock_funds_into_vault{syscall_ptr : felt*, range_check_ptr}(
    origin_chain_id : felt,
    token_low : felt,
    token_high : felt,
    token_amount_low : felt,
    token_amount_high : felt,
    signature_r_low : felt,
    signature_r_high : felt,
    signature_s_low : felt,
    signature_s_high : felt,
    signature_v : felt,
    to : felt,
    selector : felt,
    calldata_len : felt,
    calldata : felt*,
) -> ():
    alloc_locals
    let (self) = get_contract_address()
    let (caller) = get_caller_address()

    with_attr error_message("Cannot be called via execute"):
        assert_not_zero(caller - self)
    end

    let _chain_id = Uint256(low=origin_chain_id, high=0)
    let _token = Uint256(low=token_low, high=token_high)
    let _token_amount = Uint256(low=token_amount_low, high=token_amount_high)
    let _signature_r = Uint256(low=signature_r_low, high=signature_r_high)
    let _signature_s = Uint256(low=signature_s_low, high=signature_s_high)
    let _signature_v = Uint256(low=signature_v, high=0)
    let _to = felt_to_uint256(to)
    let _selector = felt_to_uint256(selector)

    let (calldata_uint256 : Uint256*) = alloc()
    from_felt_array_to_uint256_array(calldata_len, calldata, calldata_uint256)

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
    # only called via execute
    assert_only_self()

    # change signer
    with_attr error_message("eth signer cannot be null"):
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
    # only called via execute
    assert_only_self()

    # change signer
    with_attr error_message("stark signer cannot be null"):
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
func supportsInterface{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    interfaceId : felt
) -> (success : felt):
    # 165
    if interfaceId == 0x01ffc9a7:
        return (TRUE)
    end
    # IAccount
    if interfaceId == ERC165_ACCOUNT_INTERFACE:
        return (TRUE)
    end
    return (FALSE)
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
    with_attr error_message("nonce invalid"):
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
    with_attr error_message("eth signature invalid"):
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
    with_attr error_message("stark signature invalid"):
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
