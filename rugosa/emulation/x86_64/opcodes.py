﻿"""
CPU EMULATOR HANDLED INSTRUCTIONS

Add any instructions that need to be handled below.  The function should be declared as such

# Using the same function for multiple instructions:
@opcode("add")
@opcode("adc")
def _add(cpu_context, instruction):
    print "IN ADD"

# Using a single function for an opcode
@opcode
def MOV(cpu_context, instruction):
    print "IN MOV"

WARNING:
    Do NOT rely on the flags registers being correct.  There are places were flags are NOT being updated when they
    should, and the very fact that CALL instructions are skipped could cause flags to be incorrect.
"""

import logging

import dragodis
from dragodis import OperandType

from .. import utils
from ..cpu_context import ProcessorContext
from ..instruction import Instruction
from ..registry import registrar

# Dictionary containing opcode names -> function
OPCODES = {}
opcode = registrar(OPCODES, name="opcode")


logger = logging.getLogger(__name__)


@opcode
def AAA(cpu_context: ProcessorContext, instruction: Instruction):
    """ ASCII Adjust AX After Addition """
    if cpu_context.bitness == 64:
        logger.debug("Opcode not valid for 64-bit")
        return

    orig_ax = cpu_context.registers.ax

    if (cpu_context.registers.al & 0xF) > 9 or cpu_context.registers.af == 1:
        cpu_context.registers.ax += 0x106
        cpu_context.registers.af = 1
        cpu_context.registers.cf = 1
    else:
        cpu_context.registers.af = 0
        cpu_context.registers.cf = 0
    cpu_context.registers.al &= 0xF

    logger.debug("Adjusted AX 0x%X -> 0x%X", orig_ax, cpu_context.registers.ax)


@opcode
def AAD(cpu_context: ProcessorContext, instruction: Instruction):
    """ ASCII Adjust AX Before Division """
    if cpu_context.bitness == 64:
        logger.debug("Opcode not valid for 64-bit")
        return

    orig_ax = cpu_context.registers.ax

    operands = instruction.operands
    base = operands[0].value if operands else 10
    al = cpu_context.registers.al
    ah = cpu_context.registers.ah
    cpu_context.registers.al = (al + (ah * base)) & 0xFF
    cpu_context.registers.ah = 0

    logger.debug("Adjusted AX 0x%X -> 0x%X", orig_ax, cpu_context.registers.ax)


@opcode
def AAM(cpu_context: ProcessorContext, instruction: Instruction):
    """ ASCII Adjust AX After Multiply """
    if cpu_context.bitness == 64:
        logger.debug("Opcode not valid for 64-bit")
        return

    orig_ax = cpu_context.registers.ax

    operands = instruction.operands
    base = operands[0].value if operands else 10
    al = cpu_context.registers.al
    cpu_context.registers.ah = al // base
    cpu_context.registers.al = al % base

    logger.debug("Adjusted AX 0x%X -> 0x%X", orig_ax, cpu_context.registers.ax)


@opcode
def AAS(cpu_context: ProcessorContext, instruction: Instruction):
    """ ASCII Adjust AX After Subtraction """
    if cpu_context.bitness == 64:
        logger.debug("Opcode not valid for 64-bit")
        return

    orig_ax = cpu_context.registers.ax

    if (cpu_context.registers.al & 0xF) > 9 or cpu_context.registers.af == 1:
        cpu_context.registers.ax -= 6
        cpu_context.registers.ah -= 1
        cpu_context.registers.af = 1
        cpu_context.registers.cf = 1
    else:
        cpu_context.registers.cf = 0
        cpu_context.registers.af = 0
    cpu_context.registers.al &= 0xF

    logger.debug("Adjusted AX 0x%X -> 0x%X", orig_ax, cpu_context.registers.ax)


@opcode("adc")
@opcode("add")
def _add(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Handle both ADC and ADD here since the only difference is the flags.
    """
    operands = instruction.operands
    opvalue1 = operands[0].value
    opvalue2 = operands[1].value
    result = opvalue1 + opvalue2
    if instruction.mnem == "adc":
        result += cpu_context.registers.cf
    width = get_max_operand_size(operands)

    mask = utils.get_mask(width)
    cpu_context.registers.cf = int(result > mask)
    cpu_context.registers.af = int((opvalue1 ^ opvalue2 ^ result) & 0x10)
    cpu_context.registers.zf = int(result & mask == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = int(not (-(mask // 2) <= result < (mask // 2)))
    cpu_context.registers.pf = get_parity(result)
    if cpu_context.emulator.branch_tracking:
        cpu_context.jcccontext.update_flag_opnds(["cf", "af", "zf", "sf", "of", "pf"], operands)

    logger.debug("0x%X + 0x%X = 0x%X", opvalue1, opvalue2, result)
    operands[0].value = result & mask


@opcode
def AND(cpu_context: ProcessorContext, instruction: Instruction):
    """ AND logic operator """
    operands = instruction.operands
    opvalue1 = operands[0].value
    opvalue2 = operands[1].value
    result = opvalue1 & opvalue2
    width = get_max_operand_size(operands)

    cpu_context.registers.cf = 0
    cpu_context.registers.zf = int(result == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = 0
    cpu_context.registers.pf = get_parity(result)
    if cpu_context.emulator.branch_tracking:
        cpu_context.jcccontext.update_flag_opnds(["cf", "zf", "sf", "of", "pf"], operands)

    logger.debug("0x%X & 0x%X = 0x%X", opvalue1, opvalue2, result)
    operands[0].value = result


@opcode
def BSWAP(cpu_context: ProcessorContext, instruction: Instruction):
    """ byte Swap """
    operands = instruction.operands
    opvalue1 = operands[0].value
    width = operands[0].width
    result = swap_bytes(opvalue1, width)
    logger.debug("0x%X -> 0x%X", opvalue1, result)
    operands[0].value = result


@opcode
def CALL(cpu_context: ProcessorContext, instruction: Instruction):
    """
    CALL function

    Attempt to determine the number of arguments passed to the function which are purged on return
    """
    operands = instruction.operands
    # Function pointer can be a memory reference or immediate.
    func_ea = operands[0].addr or operands[0].value

    logger.debug("call %s", hex(func_ea))

    # If a valid function pointer, collect call history and emulate effects.
    if operands[0].is_func_ptr:
        # Using signature in order to get demangled name.
        try:
            func_name = cpu_context.emulator.disassembler.get_function_signature(func_ea).name
            logger.debug("call %s", func_name)
        except dragodis.NotExistError:
            logger.warning("Invalid function signature at %s", hex(func_ea))
            return

        # Push return address on the stack and set the ip to the function's start address.
        cpu_context.sp -= cpu_context.byteness
        ret_addr = instruction.next_ip
        cpu_context.memory.write(cpu_context.sp, ret_addr.to_bytes(cpu_context.byteness, cpu_context.byteorder))

        cpu_context._execute_call(func_ea, func_name, instruction.ip)

        # Pop return address from the stack, set ip to return address.
        cpu_context.sp += cpu_context.byteness
        cpu_context.ip = ret_addr
    else:
        logger.debug("Invalid function")

    if cpu_context.bitness == 64:
        return

    # Cleanup the stack based on the stack delta reported by the disassembler.
    cpu_context.sp += instruction._insn.stack_delta


@opcode
def CDQ(cpu_context: ProcessorContext, instruction: Instruction):
    """ Convert DWORD to QWORD with sign extension """
    if cpu_context.registers.eax >> 31:
        result = 0xFFFFFFFF
    else:
        result = 0x0

    logger.debug("Setting register EDX to 0x%X", result)
    cpu_context.registers.edx = result


@opcode
def CLC(cpu_context: ProcessorContext, instruction: Instruction):
    """ Clear Carry Flag """
    cpu_context.registers.cf = 0


@opcode
def CLD(cpu_context: ProcessorContext, instruction: Instruction):
    """ Clear Direction Flag """
    cpu_context.registers.df = 0


@opcode
def CMC(cpu_context: ProcessorContext, instruction: Instruction):
    """ Complement Carry Flag """
    cpu_context.registers.cf = int(not cpu_context.registers.cf)


@opcode
def CMP(cpu_context: ProcessorContext, instruction: Instruction):
    """ Compare to values """
    operands = instruction.operands
    width = get_min_operand_size(operands)
    mask = utils.get_mask(width)
    opvalue1 = operands[0].value & mask
    opvalue2 = operands[1].value & mask
    result = opvalue1 - opvalue2

    cpu_context.registers.cf = int((opvalue1 & mask) < (opvalue2 & mask))
    cpu_context.registers.af = int((opvalue1 ^ opvalue2 ^ result) & 0x10)
    cpu_context.registers.zf = int(result & mask == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = int(not (-(mask // 2) <= result < (mask // 2)))
    cpu_context.registers.pf = get_parity(result)
    if cpu_context.emulator.branch_tracking:
        cpu_context.jcccontext.update_flag_opnds(["cf", "af", "zf", "sf", "of", "pf"], operands)

    logger.debug("0x%X <-> 0x%X = 0x%X", opvalue1, opvalue2, result)


@opcode
def CMPS(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Nothing really to do for CMPS
    """
    pass


@opcode
def CMPSB(cpu_context: ProcessorContext, instruction: Instruction):
    """
    TODO: Does this really need to be implemented for our purposes???
    """
    pass


@opcode
def CMPSW(cpu_context: ProcessorContext, instruction: Instruction):
    """
    TODO: Does this really need to be implemented for our purposes???
    """
    pass


@opcode
def CMPSD(cpu_context: ProcessorContext, instruction: Instruction):
    """
    TODO: Does this really need to be implemented for our purposes???
    """
    pass


@opcode
def CQO(cpu_context: ProcessorContext, instruction: Instruction):
    """ Convert QWORD to DQWORD with sign extension """
    # Only works in 64-bit mode
    if cpu_context.bitness != 64:
        logger.debug("Opcode only available for 64-bit mode.")
        return

    if cpu_context.registers.rax >> 63:
        result = 0xFFFFFFFFFFFFFFFF
    else:
        result = 0x0

    logger.debug("Setting register RDX to 0x%X", result)
    cpu_context.registers.rdx = result


@opcode
def CVTDQ2PD(cpu_context: ProcessorContext, instruction: Instruction):
    """ Convert Packed Doubleword Integers to Packed Double-Precision Floating-Point Values """
    operands = instruction.operands
    opvalue2 = operands[1].value
    dword0 = opvalue2 & 0xFFFFFFFF
    dword1 = (opvalue2 & 0xFFFFFFFF) >> 32
    dpfp0 = utils.float_to_int(dword0)
    dpfp1 = utils.float_to_int(dword1)
    result = (dpfp1 << 64) | dpfp0
    logger.debug("0x%X -> 0x%X, 0x%X -> 0x%X --> 0x%X", dword0, dpfp0, dword1, dpfp1, result)
    operands[0].value = result


@opcode
def CVTSI2SD(cpu_context: ProcessorContext, instruction: Instruction):
    """ Convert Doubleword Int to Scalar Double-Precision Floating-Point """
    operands = instruction.operands
    opvalue2 = operands[1].value
    result = utils.float_to_int(opvalue2)
    logger.debug("int 0x%X -> float equivalent 0x%X", opvalue2, result)
    operands[0].value = result


@opcode
def CVTTSD2SI(cpu_context: ProcessorContext, instruction: Instruction):
    """ Convert with Truncation Scalar Double-Precision Floating-Point Value to Signed Integer """
    operands = instruction.operands
    opvalue2 = operands[1].value
    # width = operands[0].width
    result = int(utils.int_to_float(opvalue2))
    logger.debug("float 0x%X -> int equivalent 0x%X", opvalue2, result)
    operands[0].value = result


@opcode
def CWD(cpu_context: ProcessorContext, instruction: Instruction):
    """ Convert WORD to DWORD with sign extension """
    if cpu_context.registers.ax >> 15:
        result = 0xFFFF
    else:
        result = 0x0

    logger.debug("Setting register DX to 0x%X", result)
    cpu_context.registers.dx = result


@opcode
def DEC(cpu_context: ProcessorContext, instruction: Instruction):
    """ Decrement """
    operands = instruction.operands
    opvalue1 = operands[0].value
    width = operands[0].width
    mask = utils.get_mask(width)
    result = opvalue1 - 1

    cpu_context.registers.af = int(result & 0x0F == 0x0F)
    cpu_context.registers.zf = int(result & mask == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = int(utils.sign_bit(opvalue1, width) and not utils.sign_bit(result, width))
    cpu_context.registers.pf = get_parity(result)
    if cpu_context.emulator.branch_tracking:
        cpu_context.jcccontext.update_flag_opnds(["af", "zf", "sf", "of", "pf"], operands)

    logger.debug("0x%X - 1 = 0x%X", opvalue1, result)
    operands[0].value = result & mask


@opcode
def DIV(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Divide

    rax / op1 -> rax (rdx holds remainder)
    """
    RAX_REG_SIZE_MAP = {8: "rax", 4: "eax", 2: "ax", 1: "al"}
    RDX_REG_SIZE_MAP = {8: "rdx", 4: "edx", 2: "dx"}

    operands = instruction.operands
    divisor = operands[0].value
    width = operands[0].width
    if divisor == 0:
        # Log the instruction for a DIV / 0 error
        logger.debug("DIV / 0")
        return

    # We actually need to do some doctoring with DIV as operand 0 is implied as the EAX register of
    # a certain size.
    rax_str = RAX_REG_SIZE_MAP[width]
    dividend = cpu_context.registers[rax_str]

    result = (dividend // divisor) & utils.get_mask(width)
    remainder = (dividend % divisor) & utils.get_mask(width)
    logger.debug("0x%X / 0x%X = 0x%X", dividend, divisor, result)
    if width == 1:
        # Result stored in AL, remainder stored in AH
        cpu_context.registers.al = result
        cpu_context.registers.ah = remainder
    else:
        rdx_str = RDX_REG_SIZE_MAP[width]
        cpu_context.registers[rax_str] = result
        cpu_context.registers[rdx_str] = remainder


@opcode
def IDIV(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Signed Division
    """
    RAX_REG_SIZE_MAP = {8: "rax", 4: "eax", 2: "ax", 1: "al"}
    RDX_REG_SIZE_MAP = {8: "rdx", 4: "edx", 2: "dx"}

    operands = instruction.operands
    # Need to obtain the width of the divisor, to determine the width of the dividend
    width = operands[-1].width
    divisor = utils.signed(operands[-1].value, width)
    if divisor == 0:
        logger.debug("DIV / 0")
        return

    if width == 1:
        # When dividing by a 8-bit value, use AX
        dividend = utils.signed(cpu_context.registers.ax, 2)
        result_reg = "al"
        remainder_reg = "ah"

    else:
        # When dividing by 16-bits -> combine DX:AX
        # When dividing by 32-bits -> combine EDX:EAX
        # When dividing by 64-bits -> combine RDX:RAX
        rax_str = RAX_REG_SIZE_MAP[width]
        rdx_str = RDX_REG_SIZE_MAP[width]
        dividend = utils.signed(
            (cpu_context.registers[rdx_str] << (width * 8)) | cpu_context.registers[rax_str],
            width * 2
        )
        result_reg = rax_str
        remainder_reg = rdx_str

    result = int(dividend / divisor) & utils.get_mask(width)
    remainder = (dividend - (int(dividend / divisor) * divisor)) & utils.get_mask(width)
    logger.debug("0x%X / 0x%X = 0x%X", dividend, divisor, result)
    cpu_context.registers[result_reg] = result
    cpu_context.registers[remainder_reg] = remainder


@opcode
def DIVSD(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Divide Scalar Double-Precision Floating-Point Value

    op1 / op2 -> op1
    """
    operands = instruction.operands
    opvalue1 = utils.int_to_float(operands[0].value)
    opvalue2 = utils.int_to_float(operands[1].value)
    # Because there is no guarantee that the registers/memory have been properly initialized, ignore DIV / 0 errors.
    if opvalue2 == 0:
        # Log DIV / 0 error
        logger.debug("DIV / 0")
        return

    result = opvalue1 // opvalue2
    logger.debug("0x%X / 0x%X = 0x%X", opvalue1, opvalue2, result)
    result = utils.float_to_int(result)
    operands[0].value = result


def _mul(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Handle MUL instruction and 1-operand IMUL instruction as the same.
    """
    RAX_REG_SIZE_MAP = {8: "rax", 4: "eax", 2: "ax", 1: "al"}
    RDX_REG_SIZE_MAP = {8: "rdx", 4: "edx", 2: "dx"}

    dx_reg = None
    dx_result = None
    operands = instruction.operands
    width = get_max_operand_size(operands)
    mask = utils.get_mask(width)
    multiplier1 = cpu_context.registers[RAX_REG_SIZE_MAP[width]]  # implied operand
    # Pull right-most operand to handle both 1 and 2 operand instructions
    multiplier2 = operands[-1].value
    result = multiplier1 * multiplier2
    flags = ["cf", "of"]

    if width == 1:
        ax_reg = RAX_REG_SIZE_MAP[2]
        ax_result = result
        if instruction.mnem == "mul":
            cpu_context.registers.cf = 0
            cpu_context.registers.of = 0
    else:
        ax_reg = RAX_REG_SIZE_MAP[width]
        dx_reg = RDX_REG_SIZE_MAP[width]
        dx_result = (result & (utils.get_mask(width) << (width * 8))) >> (width * 8)
        ax_result = result & utils.get_mask(width)
        if instruction.mnem == "mul":
            if result >> (width * 8):
                cpu_context.registers.cf = 1
                cpu_context.registers.of = 1
            else:
                cpu_context.registers.cf = 0
                cpu_context.registers.of = 0

    if instruction.mnem == "imul":
        cpu_context.registers.cf = int(
            not (
                (not utils.sign_bit(multiplier1, width) and multiplier2 & mask == 0)
                or (utils.sign_bit(multiplier1, width) and multiplier2 & mask == mask)
            )
        )
        cpu_context.registers.of = cpu_context.registers.cf
        cpu_context.registers.zf = int(multiplier1 & mask == 0)
        cpu_context.registers.sf = utils.sign_bit(multiplier1, width)
        cpu_context.registers.pf = get_parity(multiplier1)
        flags.extend(["zf", "sf", "pf"])

    if cpu_context.emulator.branch_tracking:
        cpu_context.jcccontext.update_flag_opnds(flags, operands)
    logger.debug(
        "0x%X * 0x%X = 0x%X || EAX -> 0x%X || EDX -> %s",
            multiplier1, multiplier2, result, ax_result, "0x%X" % dx_result if dx_reg else ""
        )

    cpu_context.registers[ax_reg] = ax_result
    if dx_reg:
        cpu_context.registers[dx_reg] = dx_result


# TODO: Clean up mul, imul, and _mul
@opcode
def IMUL(cpu_context: ProcessorContext, instruction: Instruction):
    """ Signed Multiplication

    ; Single operand form
    imul    ecx     ; Signed multiply the value in ecx with the value in eax (et.al)

    ; Two operand form
    imul    edi, edx    ; Signed multiply the destination operand (op 0) with the source operand (op 1)

    ; Three operand form
    imul    eax, edi, 5 ; Signed multiple source operand (op 1) with the immediate value (op 2) and store in
                        ; the destination operand (op 0)

    """
    operands = instruction.operands
    width = get_max_operand_size(operands)
    insn_data = instruction.data
    # Check for REX_W indicating a long instruction, REX is 0x40 with the W bit (0x08) set
    opcode_byte = insn_data[1] if insn_data[0] == 0x48 else insn_data[0]
    # F6/F7 are 8 and 16/32 bit IMUL without truncation so just use _mul
    if opcode_byte in (0xF6, 0xF7):
        _mul(cpu_context, instruction)
        return

    multiplier1 = operands[-2].value
    multiplier2 = operands[-1].value

    mask = utils.get_mask(width)
    result = multiplier1 * multiplier2

    cpu_context.registers.cf = int(
        not (
            (not utils.sign_bit(multiplier1, width) and multiplier2 & mask == 0)
            or (utils.sign_bit(multiplier1, width) and multiplier2 & mask == mask)
        )
    )
    cpu_context.registers.of = cpu_context.registers.cf
    cpu_context.registers.zf = int(multiplier1 & mask == 0)
    cpu_context.registers.sf = utils.sign_bit(multiplier1, width)
    cpu_context.registers.pf = get_parity(multiplier1)
    if cpu_context.emulator.branch_tracking:
        cpu_context.jcccontext.update_flag_opnds(["cf", "zf", "sf", "of", "pf"], operands)

    logger.debug("0x%X * 0x%X = 0x%X", multiplier1, multiplier2, result)
    operands[0].value = result


@opcode
def INC(cpu_context: ProcessorContext, instruction: Instruction):
    """ Increment """
    operands = instruction.operands
    opvalue1 = operands[0].value

    result = opvalue1 + 1
    width = operands[0].width
    mask = utils.get_mask(width)

    logger.debug("0x%X + 1 = 0x%X", opvalue1, result)
    operands[0].value = result

    cpu_context.registers.af = int(result & 0x0F == 0)
    cpu_context.registers.zf = int(result & mask == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = int(not utils.sign_bit(opvalue1, width) and utils.sign_bit(result, width))
    cpu_context.registers.pf = get_parity(result)
    if cpu_context.emulator.branch_tracking:
        cpu_context.jcccontext.update_flag_opnds(["af", "zf", "sf", "of", "pf"], operands)


@opcode
def JMP(cpu_context: ProcessorContext, instruction: Instruction):
    """ Unconditional jump """
    operands = instruction.operands
    jump_target = operands[0].value
    cpu_context.ip = jump_target


# TODO: Not all Jcc instructions are implemented here.
# TODO: Currently, these Jcc instructions assume that the instruction that modified the flags had 2 opcodes.
#   This is not always the case, (e.g. 'inc'). Also, we should probably figure out a way to move the
#   bulk of the code into a helper function.

# For the following jump instructions, the logic is basically the same
#   1. Get all the CodeRefs from the current IP (should only ever be 2)
#   2. Remove the EA that is the target of the Jcc instruction to we know where the non-jump target is
#   3. Determine the location where our condition takes us and set condition_target_ea to that
#   4. Set the value for the alternate path
# Note that since we aren't currently handling instructions which may cause conditional jumps, we need to
# determine if we have test_opnds and abort fixing the context if we don't.
@opcode("ja")
@opcode("jnbe")
def JA_JNBE(cpu_context: ProcessorContext, instruction: Instruction):
    """ Jump Above (CF=0 && ZF=0) """
    jump_target = instruction.operands[0].value
    jump = cpu_context.registers.cf == 0 and cpu_context.registers.zf == 0
    if jump:
        cpu_context.ip = jump_target

    if not cpu_context.emulator.branch_tracking:
        return

    next_inst = instruction._insn.line.next.address

    # Set the location where the condition would take use based on our emulation and the value for the alt branch
    test_operands = cpu_context.jcccontext.get_flag_opnds(["cf", "zf"])
    if len(test_operands) != 2:
        return

    operand0, operand1 = test_operands[:2]
    cpu_context.jcccontext.alt_branch_data_dst = operand0
    if jump:
        # opnd0 > opnd1 on this branch.  Set the alternate branch value opnd0 <= opnd1
        cpu_context.jcccontext.condition_target_ea = jump_target
        cpu_context.jcccontext.alt_branch_data = operand1.value - 1
    else:
        # opnd0 <= opnd1 on this branch. Set the alternate branch value opnd0 > opnd1
        cpu_context.jcccontext.condition_target_ea = next_inst
        cpu_context.jcccontext.alt_branch_data = operand1.value + 1

    logger.debug(
        "Primary branch 0x%X, using value 0x%X for alternate branch",
            cpu_context.jcccontext.condition_target_ea, cpu_context.jcccontext.alt_branch_data
        )

@opcode("jae")
@opcode("jnb")
@opcode("jnc")
def JAE_JNB(cpu_context: ProcessorContext, instruction: Instruction):
    """ Jump Above or Equal / Jump Not Below / Jump Not Carry (CF=0) """
    jump_target = instruction.operands[0].value
    jump = cpu_context.registers.cf == 0
    if jump:
        cpu_context.ip = jump_target

    if not cpu_context.emulator.branch_tracking:
        return

    next_inst = instruction._insn.line.next.address

    # Set the location where the condition would take use based on our emulation
    test_operands = cpu_context.jcccontext.get_flag_opnds(["cf"])
    if len(test_operands) != 2:
        return

    operand0, operand1 = test_operands[:2]
    cpu_context.jcccontext.alt_branch_data_dst = operand0
    if jump:
        # opnd0 > opnd1 on this branch.  Set the alternate branch value opnd0 < opnd1
        cpu_context.jcccontext.condition_target_ea = jump_target
        cpu_context.jcccontext.alt_branch_data = operand1.value - 1
    else:
        # opnd0 < opnd1 on this branch. Set the alternate branch value opnd0 >= opnd1
        cpu_context.jcccontext.condition_target_ea = next_inst
        cpu_context.jcccontext.alt_branch_data = operand1.value + 1

    logger.debug(
        "Primary branch 0x%X, using value 0x%X for alternate branch",
            cpu_context.jcccontext.condition_target_ea, cpu_context.jcccontext.alt_branch_data
        )


@opcode("jb")
@opcode("jc")
@opcode("jnae")
def JB_JNAE(cpu_context: ProcessorContext, instruction: Instruction):
    """ Jump Below / Jump Carry / Jump Not Above or Equal (CF=1) """
    jump_target = instruction.operands[0].value
    jump = cpu_context.registers.cf
    if jump:
        cpu_context.ip = jump_target

    if not cpu_context.emulator.branch_tracking:
        return

    # Don't know the data for either path specifically, but inferences can be made that the jump target will contain
    # a value in the first operand that is less than the second operand of the compare operation.
    next_inst = instruction._insn.line.next.address

    # Set the location where the condition would take use based on our emulation
    test_operands = cpu_context.jcccontext.get_flag_opnds(["cf"])
    if len(test_operands) != 2:
        return

    operand0, operand1 = test_operands[:2]
    cpu_context.jcccontext.alt_branch_data_dst = operand0
    if jump:
        # opnd0 < opnd1 on this branch.  Set the alternate branch value opnd0 >= opnd1
        cpu_context.jcccontext.condition_target_ea = jump_target
        cpu_context.jcccontext.alt_branch_data = operand1.value + 1
    else:
        # opnd0 >= opnd1 on this branch. Set the alternate branch value opnd0 < opnd1
        cpu_context.jcccontext.condition_target_ea = next_inst
        cpu_context.jcccontext.alt_branch_data = operand1.value - 1

    logger.debug(
        "Primary branch 0x%X, using value 0x%X for alternate branch",
            cpu_context.jcccontext.condition_target_ea, cpu_context.jcccontext.alt_branch_data
        )


@opcode("jbe")
@opcode("jna")
def JBE_JNA(cpu_context: ProcessorContext, instruction: Instruction):
    """ Jump Below or Equal / Jump Not Above (CF=1 || ZF=1) """
    jump_target = instruction.operands[0].value
    jump = cpu_context.registers.cf or cpu_context.registers.zf
    if jump:
        cpu_context.ip = jump_target

    if not cpu_context.emulator.branch_tracking:
        return

    # Don't know the data for either path specifically, but inferences can be made that the jump target will contain
    # a value in the first operand that is less than or equal to the second operand of the compare operation.
    next_inst = instruction._insn.line.next.address

    # Set the location where the condition would take use based on our emulation
    test_operands = cpu_context.jcccontext.get_flag_opnds(["cf", "zf"])
    if len(test_operands) != 2:
        return

    operand0, operand1 = test_operands[:2]
    cpu_context.jcccontext.alt_branch_data_dst = operand0
    if jump:
        # opnd0 <= opnd1 on this branch.  Set the alternate branch value opnd0 > opnd1
        cpu_context.jcccontext.condition_target_ea = jump_target
        cpu_context.jcccontext.alt_branch_data = operand1.value + 1
    else:
        # opnd0 > opnd1 on this branch.  Set the alternate branch value opnd0 <= opnd1
        cpu_context.jcccontext.condition_target_ea = next_inst
        cpu_context.jcccontext.alt_branch_data = operand1.value - 1

    logger.debug(
        "Primary branch 0x%X, using value 0x%X for alternate branch",
            cpu_context.jcccontext.condition_target_ea, cpu_context.jcccontext.alt_branch_data
        )


@opcode("je")
@opcode("jz")
def JE_JZ(cpu_context: ProcessorContext, instruction: Instruction):
    """ Jump Equal / Jump Zero (ZF=1) """
    jump_target = instruction.operands[0].value
    jump = cpu_context.registers.zf
    if jump:
        cpu_context.ip = jump_target

    if not cpu_context.emulator.branch_tracking:
        return

    # Jump target contains the known data which is either 0 or the value of the second operand of the compare operation.
    next_inst = instruction._insn.line.next.address

    # Set the location where the condition would take use based on our emulation
    test_operands = cpu_context.jcccontext.get_flag_opnds(["zf"])
    if len(test_operands) != 2:
        return

    operand0, operand1 = test_operands[:2]
    cpu_context.jcccontext.alt_branch_data_dst = operand0
    # There is additional logic that must be conducted for this jump.  If the src and dst operands are the same, then
    # the check was likely to determine if the value was 0 or not 0.  Else, the check was determining if src and dst
    # were equal.
    if jump:
        # Indicates emulation likely produced two operands which were equal, or an operand which was 0, so set the
        # alternate branch to equal the value of operand 1 + 1.  Or the comparison was to check if an operand was 0.
        # eg:  cmp    eax, 0x3D     ; eax = 0x3D
        #      cmp    eax, 0x00     ; eax = 0
        #      test   rax, rax      ; rax = 0
        cpu_context.jcccontext.condition_target_ea = jump_target
        # There is no need to check if the operands are the same here.  If the check was for equality, then adding
        # 1 to the second operand will make the check not equal.  If the check was for 0 (both operands were the same),
        # simply adding 1 to 0 will make the test fail.
        cpu_context.jcccontext.alt_branch_data = operand1.value + 1
    else:
        # Indicates emulation likely produced two operands which were not equal, or an operand which was not 0, so set
        # the alternate branch to equal the value of operand 1.  Or the comparison was to check if an operand was 0.
        # eg:  cmp    eax, 0x3D     ; eax = 0
        #      cmp    eax, 0x00     ; eax = 7
        #      test   rax, rax      ; rax = 10
        cpu_context.jcccontext.condition_target_ea = next_inst
        # Need to determine if both operands are the same.  If they are, then the check was actually to determine
        # if the value was 0.  In this case, to make the test succeed, just set the value to 0.  Otherwise the test
        # was to compare two different operands for equality, so just set the first operand to the value of the second.
        if operand0.text == operand1.text:
            cpu_context.jcccontext.alt_branch_data = 0
        else:
            cpu_context.jcccontext.alt_branch_data = operand1.value

    logger.debug(
        "Primary branch 0x%X, using value 0x%X for alternate branch",
            cpu_context.jcccontext.condition_target_ea, cpu_context.jcccontext.alt_branch_data
        )


@opcode("jg")
@opcode("jnle")
def JG_JNLE(cpu_context: ProcessorContext, instruction: Instruction):
    """ Jump Greater / Jump Not Less or Equal (ZF=0 && SF=OF) """
    jump_target = instruction.operands[0].value
    jump = cpu_context.registers.zf == 0 and cpu_context.registers.sf == cpu_context.registers.of
    if jump:
        cpu_context.ip = jump_target

    if not cpu_context.emulator.branch_tracking:
        return

    next_inst = instruction._insn.line.next.address

    # Don't know the data for either path specifically, but inferences can be made that the jump target will contain
    # a value in the first operand that is larger than the second operand of the compare operation.

    # Set the location where the condition we would take used based on our emulation
    test_operands = cpu_context.jcccontext.get_flag_opnds(["zf", "sf"])
    if len(test_operands) != 2:
        return

    operand0, operand1 = test_operands[:2]
    cpu_context.jcccontext.alt_branch_data_dst = operand0
    if jump:
        # opnd0 > opnd1 on this branch.  Set alternate branch value opnd0 <= opnd1
        cpu_context.jcccontext.condition_target_ea = jump_target
        cpu_context.jcccontext.alt_branch_data = operand1.value - 1
    else:
        # opnd0 <= opnd1on this branch.  Set alternate branch value opnd0 > opnd1
        cpu_context.jcccontext.condition_target_ea = next_inst
        cpu_context.jcccontext.alt_branch_data = operand1.value + 1

    logger.debug(
        "Primary branch 0x%X, using value 0x%X for alternate branch",
            cpu_context.jcccontext.condition_target_ea, cpu_context.jcccontext.alt_branch_data
        )


@opcode("jge")
@opcode("jnl")
def JGE_JNL(cpu_context: ProcessorContext, instruction: Instruction):
    """ Jump Greater or Equal (SF=OF) """
    jump_target = instruction.operands[0].value
    jump = cpu_context.registers.sf == cpu_context.registers.of
    if jump:
        cpu_context.ip = jump_target

    if not cpu_context.emulator.branch_tracking:
        return

    # Don't know the data for either path specifically, but inferences can be made that the jump target will contain
    # a value in the first operand that is larger than or equal to the second operand of the compare operation.
    next_inst = instruction._insn.line.next.address

    # Set the location where the condition we would take used based on our emulation
    test_operands = cpu_context.jcccontext.get_flag_opnds(["sf", "of"])
    if len(test_operands) != 2:
        return

    operand0, operand1 = test_operands[:2]
    cpu_context.jcccontext.alt_branch_data_dst = operand0
    if jump:
        # opnd0 >= opnd1 on this branch. Set alternate branch value opnd0 < opnd1
        cpu_context.jcccontext.condition_target_ea = jump_target
        cpu_context.jcccontext.alt_branch_data = operand1.value - 1
    else:
        # opnd0 < opnd1 on this branch. Set alternate branch value opnd0 >= opnd1
        cpu_context.jcccontext.condition_target_ea = next_inst
        cpu_context.jcccontext.alt_branch_data = operand1.value + 1

    logger.debug(
        "Primary branch 0x%X, using value 0x%X for alternate branch",
            cpu_context.jcccontext.condition_target_ea, cpu_context.jcccontext.alt_branch_data
        )


@opcode("jl")
@opcode("jnge")
def JL_JNGE(cpu_context: ProcessorContext, instruction: Instruction):
    """ Jump Less (SF!=OF) """
    jump_target = instruction.operands[0].value
    jump = cpu_context.registers.sf != cpu_context.registers.of
    if jump:
        cpu_context.ip = jump_target

    if not cpu_context.emulator.branch_tracking:
        return

    # Don't know the data for either path specifically, but inferences can be made that the jump target will contain
    # a value in the first operand that is less than the second operand of the compare operation.
    next_inst = instruction._insn.line.next.address

    # Set the location where the condition we would take used based on our emulation
    test_operands = cpu_context.jcccontext.get_flag_opnds(["sf", "of"])
    if len(test_operands) != 2:
        return

    operand0, operand1 = test_operands[:2]
    cpu_context.jcccontext.alt_branch_data_dst = operand0
    if jump:
        # opnd0 < opnd1 on this branch.  Set alternate branch value opnd0 >= opnd1
        cpu_context.jcccontext.condition_target_ea = jump_target
        cpu_context.jcccontext.alt_branch_data = operand1.value + 1
    else:
        # opnd1 >= opnd1 on this branch.  Set alternate branch value opnd0 < opnd1
        cpu_context.jcccontext.condition_target_ea = next_inst
        cpu_context.jcccontext.alt_branch_data = operand1.value - 1

    logger.debug(
        "Primary branch 0x%X, using value 0x%X for alternate branch",
            cpu_context.jcccontext.condition_target_ea, cpu_context.jcccontext.alt_branch_data
        )


@opcode("jle")
@opcode("jng")
def JLE_JNG(cpu_context: ProcessorContext, instruction: Instruction):
    """ Jump Less or Equal (ZF=1 || SF!=OF) """
    jump_target = instruction.operands[0].value
    jump = cpu_context.registers.zf or cpu_context.registers.sf != cpu_context.registers.of
    if jump:
        cpu_context.ip = jump_target

    if not cpu_context.emulator.branch_tracking:
        return

   # Don't know the data for either path specifically, but inferences can be made that the jump target will contain
    # a value in the first operand that is less than or equal to the second operand of the compare operation.
    next_inst = instruction._insn.line.next.address

    # Set the location where the condition we would take used based on our emulation
    test_operands = cpu_context.jcccontext.get_flag_opnds(["zf", "sf", "of"])
    if len(test_operands) != 2:
        return

    operand0, operand1 = test_operands[:2]
    cpu_context.jcccontext.alt_branch_data_dst = operand0
    if jump:
        # opnd0 <= opnd2 on this branch.  Set alternate branch value opnd1 > opnd2
        cpu_context.jcccontext.condition_target_ea = jump_target
        cpu_context.jcccontext.alt_branch_data = operand1.value + 1
    else:
        # opnd0 > opnd2 on this branch.  Set alternate branch value opnd0 <= opnd2
        cpu_context.jcccontext.condition_target_ea = next_inst
        cpu_context.jcccontext.alt_branch_data = operand1.value - 1

    logger.debug(
        "Primary branch 0x%X, using value 0x%X for alternate branch",
            cpu_context.jcccontext.condition_target_ea, cpu_context.jcccontext.alt_branch_data
        )


@opcode("jne")
@opcode("jnz")
def JNE_JNZ(cpu_context: ProcessorContext, instruction: Instruction):
    """ Jump Not Equal (ZF=0) """
    jump_target = instruction.operands[0].value
    jump = cpu_context.registers.zf == 0
    if jump:
        cpu_context.ip = jump_target

    if not cpu_context.emulator.branch_tracking:
        return

    next_inst = instruction._insn.line.next.address

    # Whatever the operation, it either set ZF or it didn't... Typically, the assumption can probably be made that
    # either the operands were equal such that a subtraction resulted in 0, or they weren't.
    # TODO: Does the compare instruction have an effect on which operand is the value to be used?

    ## Set the target for which to modify the context, it will be the only address left in code_refs
    test_operands = cpu_context.jcccontext.get_flag_opnds(["zf"])
    if len(test_operands) != 2:
        return

    operand0, operand1 = test_operands[:2]
    cpu_context.jcccontext.alt_branch_data_dst = operand0
    # There is additional logic that must be conducted for this jump.  If the src and dst operands are the same, then
    # the check was likely determine if the value was 0 or not 0.  Else, the check was determining if src and dst were
    # not equal.
    if jump:
        # Indicates emulation likely produced two operands which were not equal, or an operand which was not 0, so set
        # the alternate branch to equal the value of operand 1 (which would also be 0).  Or the comparison was to check
        # if an operand was 0.
        # eg:  cmp    eax, 0x3D     ; eax = 0
        #      cmp    eax, 0x00     ; eax = 7
        #      test   rax, rax      ; rax = 10
        cpu_context.jcccontext.condition_target_ea = jump_target
        # Need to determine if the operands are the same operand (indicating a test for 0).  If the operands are the
        # same operand, then set the value to 0.  If the operands were not the same operand, the test was for
        # equality, so set the values to the same value.
        if operand0.text == operand1.text:
            cpu_context.jcccontext.alt_branch_data = 0
        else:
            cpu_context.jcccontext.alt_branch_data = operand1.value
    else:
        # Indicates emulation likely produced two operands which were equal, or an operand was 0, so set the
        # alternate branch to the value of operand 1 + 1.  Or the comparison was to check if an operand was 0.
        # eg:  cmp    eax, 0x00     ; eax = 0
        #      cmp    eax, 0x3D     ; eax = 0x3D
        #      test   rax, rax      ; rax = 0
        cpu_context.jcccontext.condition_target_ea = next_inst
        # There is no need to check if the operands were the same.  If the operands were the same, the test was to
        # determine if the operand was 0, so just adding 1 to the operand will be enough to create the false condition.
        # If the operands weren't the same, the check was to determine if the operands were equal, so adding 1 to
        # the second operand will be enough to make the condition false.
        cpu_context.jcccontext.alt_branch_data = operand1.value + 1

    logger.debug(
        "Primary branch 0x%X, using value 0x%X for alternate branch",
            cpu_context.jcccontext.condition_target_ea, cpu_context.jcccontext.alt_branch_data
        )


@opcode
def JNO(cpu_context: ProcessorContext, instruction: Instruction):
    """ Jump Not Overflow (OF=0) """
    if not cpu_context.registers.of:
        cpu_context.ip = instruction.operands[0].value


@opcode("jnp")
@opcode("jpo")
def JNP_JPO(cpu_context: ProcessorContext, instruction: Instruction):
    """ Jump Not Parity (PF=0) """
    if not cpu_context.registers.pf:
        cpu_context.ip = instruction.operands[0].value


@opcode
def JNS(cpu_context: ProcessorContext, instruction: Instruction):
    """ Jump Not Sign (SF=0) """
    if not cpu_context.registers.sf:
        cpu_context.ip = instruction.operands[0].value


@opcode
def JO(cpu_context: ProcessorContext, instruction: Instruction):
    """ Jump Overflow (OF=1) """
    if cpu_context.registers.of:
        cpu_context.ip = instruction.operands[0].value


@opcode("jp")
@opcode("jpe")
def JP_JPE(cpu_context: ProcessorContext, instruction: Instruction):
    """ Jump Parity (PF=1) """
    if cpu_context.registers.pf:
        cpu_context.ip = instruction.operands[0].value


@opcode
def JS(cpu_context: ProcessorContext, instruction: Instruction):
    """ Jump Sign (SF=1) """
    if cpu_context.registers.sf:
        cpu_context.ip = instruction.operands[0].value


@opcode
def LEA(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Handle the LEA instruction.
    """
    operands = instruction.operands
    address = operands[1].addr
    logger.debug("Copy address 0x%X into %s", address, operands[0].text)
    operands[0].value = address


@opcode("mov")
@opcode("movzx")
@opcode("movapd")
@opcode("movaps")
@opcode("movdqa")
@opcode("movdqu")
@opcode("movupd")
@opcode("movups")
def _mov(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Handle the MOV, MOVZX, MOVA*, MOVD*, MOVU* instructions in the same manner.

    MOVZX is a zero extend, but this logic makes no real sense in python.

    NOTE: Since the widths are already taken into account when the operand values are retrieved
    or set, the logic for most mov* instructions are the same.
    """
    operands = instruction.operands
    opvalue2 = operands[1].value
    logger.debug("Copy 0x%X into %s", opvalue2, operands[0].text)
    operands[0].value = opvalue2


@opcode("movsx")
@opcode("movsxd")
def _movsx(cpu_context: ProcessorContext, instruction: Instruction):
    """ Move with Sign Extend """
    operands = instruction.operands
    opvalue2 = operands[1].value
    logger.debug("Sign-extend 0x%X into %s", opvalue2, operands[0].text)
    size = utils.sign_extend(opvalue2, operands[1].width, operands[0].width)
    operands[0].value = size


@opcode("movs")  # I don't believe IDA will ever use just "movs", but it's here just incase.
@opcode("movsb")
@opcode("movsw")
@opcode("movsd")
@opcode("movsq")
def movs(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Move Scalar Double-Precision Floating-Point Value
    OR
    Move Data from String to String
    """
    operands = instruction.operands
    # Scalar Double-Precision Floating-point move
    # Need to amend this to take into account the VEX and EVEX prefixes (not sure what they are at this point)
    # references:
    #   en.wikipedia.org/wiki/VEX_prefix
    #   en.wikipedia.org/wiki/EVEX_prefix
    #if instruction.mnem == "movsd" and len(operands) == 2:
    if instruction.data[0] == 0xF2:
        op1, op2 = operands
        data = op2.value
        if op1.type == OperandType.register:
            # When moving into an XMM register, the high 64 bits needs to remain untouched.
            data = (data & 0xFFFFFFFFFFFFFFFF0000000000000000) | data
        logger.debug("0x%X -> 0x%X", op2.value, data)
        op1.value = data

    # movs*
    else:
        if cpu_context.bitness == 16:
            src = "si"
            dst = "di"
        # 0x67 indicates 32-bit addressing
        elif cpu_context.bitness == 64 and instruction.data[0] != 0x67:
            src = "rsi"
            dst = "rdi"
        else:
            src = "esi"
            dst = "edi"
        # IDA sometimes provides a single "fake" operand to help determine the size.
        width = operands[0].width if operands else 4

        size = {"movs": width, "movsb": 1, "movsw": 2, "movsd": 4, "movsq": 8}[instruction.mnem]
        src_ptr = cpu_context.registers[src]
        dst_ptr = cpu_context.registers[dst]
        logger.debug("0x%X -> 0x%X", src_ptr, dst_ptr)
        cpu_context.memory.copy(src_ptr, dst_ptr, size)

        # update ESI/EDI registers
        if cpu_context.registers.df:
            cpu_context.registers[src] -= size
            cpu_context.registers[dst] -= size
        else:
            cpu_context.registers[src] += size
            cpu_context.registers[dst] += size


@opcode
def MOVD(cpu_context: ProcessorContext, instruction: Instruction):
    """ Move Dword """
    operands = instruction.operands
    opvalue2 = operands[1].value & 0xFFFFFFFF
    logger.debug("Copy 0x%X into %s", opvalue2, operands[0].text)
    operands[0].value = opvalue2


@opcode
def MOVQ(cpu_context: ProcessorContext, instruction: Instruction):
    """ Move Quadword """
    operands = instruction.operands
    opvalue2 = operands[1].value & 0xFFFFFFFFFFFFFFFF
    logger.debug("Copy 0x%X into %s", opvalue2, operands[0].text)
    operands[0].value = opvalue2


@opcode
def MUL(cpu_context: ProcessorContext, instruction: Instruction):
    """ Multiplication """
    _mul(cpu_context, instruction)


@opcode
def NEG(cpu_context: ProcessorContext, instruction: Instruction):
    """ Negate """
    operands = instruction.operands
    opvalue1 = operands[0].value
    result = -opvalue1
    width = operands[0].width
    mask = utils.get_mask(width)

    cpu_context.registers.cf = int(result & mask != 0)
    cpu_context.registers.af = int(result & 0x0F != 0)
    cpu_context.registers.zf = int(result & mask == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = int(utils.sign_bit(opvalue1, width) and not utils.sign_bit(result, width))
    if cpu_context.emulator.branch_tracking:
        cpu_context.jcccontext.update_flag_opnds(["cf", "af", "zf", "sf", "of"], operands)

    logger.debug("0x%X - 0x%X", opvalue1, result)
    operands[0].value = result


@opcode
def NOT(cpu_context: ProcessorContext, instruction: Instruction):
    """ NOT Logic Operator """
    operands = instruction.operands
    opvalue1 = operands[0].value
    result = ~opvalue1
    logger.debug("0x%X -> 0x%X", opvalue1, result)
    operands[0].value = result


@opcode
def OR(cpu_context: ProcessorContext, instruction: Instruction):
    """ OR Logic Operator """
    operands = instruction.operands
    opvalue1 = operands[0].value
    opvalue2 = operands[1].value
    width = get_max_operand_size(operands)
    result = opvalue1 | opvalue2

    cpu_context.registers.cf = 0
    cpu_context.registers.zf = int(result == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = 0
    cpu_context.registers.pf = get_parity(result)
    if cpu_context.emulator.branch_tracking:
        cpu_context.jcccontext.update_flag_opnds(["cf", "zf", "sf", "of", "pf"], operands)

    logger.debug("0x%X | 0x%X = 0x%X", opvalue1, opvalue2, result)
    operands[0].value = result


@opcode
def POP(cpu_context: ProcessorContext, instruction: Instruction):
    """ POP stack value """
    operands = instruction.operands
    data = cpu_context.memory.read(cpu_context.sp, cpu_context.byteness)
    result = int.from_bytes(data, cpu_context.byteorder)
    cpu_context.sp += cpu_context.byteness
    logger.debug("Popped value 0x%X into %s", result, operands[0].text)
    operands[0].value = result


@opcode("popa")
@opcode("popad")
def POPA(cpu_context: ProcessorContext, instruction: Instruction):
    """
    POPA (valid only for x86)

    NOTE: This function will return None.  This is one instance where accessing the registers directly makes more
            sense.
    """
    # NOTE Some assemblers may force size based on operand size instead of mnem.
    # However, IDA should set the proper mnemonic for us.
    if instruction.mnem.endswith("d"):
        reg_order = ["edi", "esi", "ebp", "esp", "ebx", "edx", "ecx", "eax"]
    else:
        reg_order = ["di", "si", "bp", "sp", "bx", "dx", "cx", "ax"]

    for reg in reg_order:
        if reg not in ("esp", "sp"):
            # reg <- Pop()
            data = cpu_context.memory.read(cpu_context.registers.esp, cpu_context.byteness)
            val = int.from_bytes(data, cpu_context.byteorder)
            cpu_context.registers[reg] = val
            logger.debug("Popped value 0x%X into %s", val, reg)
        cpu_context.sp += cpu_context.byteness


@opcode("popf")
@opcode("popfd")
@opcode("popfq")
def POPF(cpu_context: ProcessorContext, instruction: Instruction):
    """ Pop FLAGS/EFLAGS register off the stack """
    data = cpu_context.memory.read(cpu_context.sp, cpu_context.byteness)
    flags = int.from_bytes(data, cpu_context.byteorder)
    cpu_context.sp += cpu_context.byteness

    logger.debug("Popped value 0x%X into flags register", flags)
    if cpu_context.bitness == 16:
        cpu_context.registers.flags = flags
    else:
        # Also works for RFLAGS. Since we don't support them, they are all zeros.
        cpu_context.registers.eflags = flags


@opcode
def PUSH(cpu_context: ProcessorContext, instruction: Instruction):
    """ PUSH """
    operand = instruction.operands[0]
    value = utils.unsigned(operand.value, operand.width)
    logger.debug("Pushing 0x%X onto stack", value)
    cpu_context.registers.rsp -= cpu_context.byteness
    cpu_context.memory.write(
        cpu_context.registers.esp,
        value.to_bytes(operand.width, cpu_context.byteorder)
    )


@opcode("pusha")
@opcode("pushad")
def PUSHA(cpu_context: ProcessorContext, instruction: Instruction):
    """ Push all general-purpose registers (valid only for x86) """
    # NOTE Some assemblers may force size based on operand size instead of mnem.
    # However, IDA should set the proper mnemonic for us.
    if instruction.mnem.endswith("d"):
        reg_order = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
        orig_esp = cpu_context.registers.esp
    else:
        reg_order = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"]
        orig_esp = cpu_context.registers.sp

    for reg in reg_order:
        cpu_context.sp -= cpu_context.byteness
        pushed_value = orig_esp if reg in ("esp", "sp") else cpu_context.registers[reg]
        logger.debug("Pushing 0x%X onto stack", pushed_value)
        cpu_context.memory.write(
            cpu_context.registers.esp,
            pushed_value.to_bytes(cpu_context.byteness, cpu_context.byteorder),
        )


@opcode("pushf")
@opcode("pushfd")
@opcode("pushfq")
def PUSHF(cpu_context: ProcessorContext, instruction: Instruction):
    """ Push FLAGS/EFLAGS register onto the stack """
    if cpu_context.bitness == 16:
        flags = cpu_context.registers.flags
    else:
        # Also works for RFLAGS. Since we don't support them, they are all zeros.
        flags = cpu_context.registers.eflags

    # VM and RF flags are not copied.
    flags &= ~0x10000  # rf
    flags &= ~0x20000  # vm

    logger.debug("Pushing 0x%X onto the stack", flags)
    cpu_context.sp -= cpu_context.byteness
    cpu_context.memory.write(
        cpu_context.sp,
        flags.to_bytes(cpu_context.byteness, cpu_context.byteorder),
    )


@opcode
def RCR(cpu_context: ProcessorContext, instruction: Instruction):
    """ Rotate Carry Right """
    operands = instruction.operands
    opvalue1 = operands[0].value
    opvalue2 = operands[1].value
    width = get_max_operand_size(operands)

    # Because we want to allow for 64-bit code, we'll use 0x3F as our mask.
    if width == 8:
        tempcount = opvalue2 & (0x3F if cpu_context.bitness == 64 else 0x1F)
    elif width in [1, 2, 4]:
        # Basically MOD by 9, 17, 33 when the width is 1 byte, 2 bytes or 4 bytes
        tempcount = (opvalue2 & (0x3F if cpu_context.bitness == 64 else 0x1F)) % ((width * 8) + 1)
    else:
        # This is undefined behavior
        return

    if opvalue2 == 1:
        cpu_context.registers.of = get_msb(opvalue1, width) ^ cpu_context.registers.cf

    while tempcount:
        tempcf = get_lsb(opvalue2)
        opvalue1 = (opvalue1 >> 1) + (cpu_context.registers.cf * 2 ** width)
        cpu_context.registers.cf = tempcf
        tempcount -= 1

    if cpu_context.emulator.branch_tracking:
        cpu_context.jcccontext.update_flag_opnds(["cf"], operands)
    logger.debug("Rotate 0x%X right by 0x%X -> 0x%X",
                 operands[0].value, opvalue2, opvalue1)
    operands[0].value = opvalue1


@opcode
def RCL(cpu_context: ProcessorContext, instruction: Instruction):
    """ Rotate Carry Left """
    operands = instruction.operands
    opvalue1 = operands[0].value
    opvalue2 = operands[1].value
    width = get_max_operand_size(operands)

    # Because we want to allow for 64-bit code, we'll use 0x3F as our mask.
    if width == 8:
        tempcount = opvalue2 & (0x3F if cpu_context.bitness == 64 else 0x1F)
    elif width in [1, 2, 4]:
        # Basically MOD by 9, 17, 33 when width is 1 byte, 2 bytes or 4 bytes
        tempcount = (opvalue2 & (0x3F if cpu_context.bitness == 64 else 0x1F)) % ((width * 8) + 1)
    else:
        # This is undefined behavior
        return

    while tempcount:
        tempcf = get_msb(opvalue1, width)
        opvalue1 = (opvalue1 * 2) + cpu_context.registers.cf
        cpu_context.registers.cf = tempcf
        tempcount -= 1

    if opvalue2 == 1:
        cpu_context.registers.of = get_msb(opvalue1, width) ^ cpu_context.registers.cf

    if cpu_context.emulator.branch_tracking:
        cpu_context.jcccontext.update_flag_opnds(["cf", "of"], operands)
    logger.debug("Rotate 0x%X left by 0x%X -> 0x%X",
                 operands[0].value, opvalue2, opvalue1)
    operands[0].value = opvalue1


@opcode
def ROL(cpu_context: ProcessorContext, instruction: Instruction):
    """ Rotate Left """
    operands = instruction.operands
    opvalue1 = operands[0].value
    opvalue2 = operands[1].value
    width = get_max_operand_size(operands)

    # Because we want to allow for 64-bit code, we'll use 0x3F as our mask.
    if width == 8:
        tempcount = opvalue2 & (0x3F if cpu_context.bitness == 64 else 0x1F)
    elif width in [1, 2, 4]:
        # Basically MOD by 8, 16, 32 when width is 1 byte, 2 bytes or 4 bytes
        tempcount = (opvalue2 & (0x3F if cpu_context.bitness == 64 else 0x1F)) % (width * 8)
    else:
        # This is undefined behavior
        return

    if tempcount > 0:
        mask = utils.get_mask(width)
        while tempcount:
            opvalue1 = (opvalue1 * 2) + get_msb(opvalue1, width)
            opvalue1 &= mask
            tempcount -= 1

        cpu_context.registers.cf = get_lsb(opvalue1)
        if opvalue2 == 1:
            cpu_context.registers.of = get_msb(opvalue1, width) ^ cpu_context.registers.cf

    if cpu_context.emulator.branch_tracking:
        cpu_context.jcccontext.update_flag_opnds(["cf", "of"], operands)
    logger.debug("Rotate 0x%X left by 0x%X -> 0x%X",
                 operands[0].value, opvalue2, opvalue1)
    operands[0].value = opvalue1


@opcode
def ROR(cpu_context: ProcessorContext, instruction: Instruction):
    """ Rotate Right """
    operands = instruction.operands
    opvalue1 = operands[0].value
    opvalue2 = operands[1].value
    width = get_max_operand_size(operands)

    # Because we want to allow for 64-bit code, we'll use 0x3F as our mask.
    if width == 8:
        tempcount = opvalue2 & (0x3F if cpu_context.bitness == 64 else 0x1F)
    elif width in [1, 2, 4]:
        # Basically MOD by 8, 16, 32 when width is 1 byte, 2 bytes or 4 bytes
        tempcount = (opvalue2 & (0x3F if cpu_context.bitness == 64 else 0x1F)) % (width * 8)
    else:
        # This is undefined behavior
        return

    if tempcount > 0:
        while tempcount:
            tempcf = get_lsb(opvalue2)
            opvalue1 = (opvalue1 >> 1) + (tempcf * 2 ** width)
            tempcount -= 1

        cpu_context.registers.cf = get_msb(opvalue1, width)
        if opvalue2 == 1:
            cpu_context.registers.of = get_msb(opvalue1, width) ^ (get_msb(opvalue1, width) - 1)

    if cpu_context.emulator.branch_tracking:
        cpu_context.jcccontext.update_flag_opnds(["cf", "of"], operands)
    logger.debug("Rotate 0x%X right by 0x%X -> 0x%X",
                 operands[0].value, opvalue2, opvalue1)
    operands[0].value = opvalue1


@opcode("sal")
@opcode("shl")
def sal_shl(cpu_context: ProcessorContext, instruction: Instruction):
    """ Shift Arithmetic Left """
    operands = instruction.operands
    opvalue1 = operands[0].value
    opvalue2 = operands[1].value
    width = get_max_operand_size(operands)
    result = opvalue1

    if opvalue2:
        # 0x3F Because we want to allow for 64-bit code
        tempcount = opvalue2 & (0x3F if cpu_context.bitness == 64 else 0x1F)
        mask = utils.get_mask(width)
        while tempcount:
            cpu_context.registers.cf = get_msb(result, width)
            result *= 2
            result &= mask
            tempcount -= 1

        result &= utils.get_mask(width)

        bit_count = width * 8
        if opvalue2 <= bit_count:
            cpu_context.registers.cf = (opvalue1 >> (bit_count - opvalue2)) & 0x01
        else:
            cpu_context.registers.cf = 0
        cpu_context.registers.sf = utils.sign_bit(result, width)
        if opvalue2 == 1:
            cpu_context.registers.of = utils.sign_bit(opvalue1 ^ result, width)
        else:
            cpu_context.registers.of = utils.sign_bit((opvalue1 << (opvalue2 - 1)) ^ result, width)

    if cpu_context.emulator.branch_tracking:
        cpu_context.jcccontext.update_flag_opnds(["cf", "of"], operands)
    logger.debug("Shift 0x%X left by 0x%X -> 0x%X", opvalue1, opvalue2, result)
    operands[0].value = result


@opcode
def SAR(cpu_context: ProcessorContext, instruction: Instruction):
    """ Shift Arithmetic Right """
    operands = instruction.operands
    opvalue1 = operands[0].value
    opvalue2 = operands[1].value
    width = get_max_operand_size(operands)
    result = opvalue1
    if opvalue2:
        # 0x3F Because we want to allow for 64-bit code
        tempcount = opvalue2 & (0x3F if cpu_context.bitness == 64 else 0x1F)
        msb = get_msb(opvalue1, cpu_context.byteness)
        while tempcount:
            cpu_context.registers.cf = get_lsb(result)
            result = result >> 1
            tempcount -= 1

        bit_count = width * 8
        if opvalue2 < bit_count:
            cpu_context.registers.cf = (opvalue1 >> (opvalue2 - 1)) & 0x01
        else:
            cpu_context.registers.cf = utils.sign_bit(opvalue1, width)
        cpu_context.registers.zf = int(result == 0)
        cpu_context.registers.sf = utils.sign_bit(result, width)
        cpu_context.registers.of = 0
        cpu_context.registers.pf = get_parity(result)

        result |= msb << cpu_context.bitness

    if cpu_context.emulator.branch_tracking:
        cpu_context.jcccontext.update_flag_opnds(["cf", "zf", "sf", "of", "pf"], operands)
    logger.debug("Shift 0x%X right by 0x%X -> 0x%X", opvalue1, opvalue2, result)
    operands[0].value = result


@opcode
def SBB(cpu_context: ProcessorContext, instruction: Instruction):
    """ Subtract with Borrow/Carry """
    operands = instruction.operands
    opvalue1 = operands[0].value
    opvalue2 = operands[1].value
    width = get_max_operand_size(operands)
    mask = utils.get_mask(width)
    result = opvalue1 - (opvalue2 + cpu_context.registers.cf)

    cpu_context.registers.af = int((opvalue1 ^ opvalue2 ^ result) & 0x10)
    cpu_context.registers.zf = int(result == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = int(not (-(mask // 2) <= result < (mask // 2)))
    cpu_context.registers.pf = get_parity(result)
    if cpu_context.emulator.branch_tracking:
        cpu_context.jcccontext.update_flag_opnds(["af", "zf", "sf", "of", "pf"], operands)
    logger.debug("0x%X - 0x%X = 0x%X",
                 opvalue1, (opvalue2 + cpu_context.registers.cf), result)
    operands[0].value = result


@opcode("scas")
@opcode("scasb")
@opcode("scasw")
@opcode("scasd")
def scas(cpu_context: ProcessorContext, instruction: Instruction):
    """ Scan string """
    if cpu_context.bitness == 16:
        edi_reg = "di"
    else:
        edi_reg = "edi"

    mnem = instruction.mnem
    if mnem.endswith("b"):
        width = 1
    elif mnem.endswith("w"):
        width = 2
    elif mnem.endswith("d"):
        width = 4
    else:
        width = instruction.operands[0].width

    eax_reg = {1: "al", 2: "ax", 4: "eax"}[width]

    # Compare value in eax with value at memory location stored in edi.
    opvalue1 = cpu_context.registers[eax_reg]
    data = cpu_context.memory.read(cpu_context.registers[edi_reg], width)
    opvalue2 = int.from_bytes(data, cpu_context.byteorder)
    result = opvalue1 - opvalue2
    logger.debug("Scan compare 0x%X - 0x%X = 0x%X", opvalue1, opvalue2, result)

    mask = utils.get_mask(width)
    cpu_context.registers.cf = int((opvalue1 & mask) < (opvalue2 & mask))
    cpu_context.registers.af = int((opvalue1 ^ opvalue2 ^ result) & 0x10)
    cpu_context.registers.zf = int(result & mask == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = int(not (-(mask // 2) <= result < (mask // 2)))
    cpu_context.registers.pf = get_parity(result)
    # TODO: Can't branch track because no real operands.
    # if cpu_context.emulator.branch_tracking:
    #     cpu_context.jcccontext.update_flag_opnds(["cf", "af", "zf", "sf", "of", "pf"], operands)

    # Update or decrement edi
    if cpu_context.registers.df:
        cpu_context.registers[edi_reg] -= width
    else:
        cpu_context.registers[edi_reg] += width


@opcode
def SETNA(cpu_context: ProcessorContext, instruction: Instruction):
    """ Set if Not Above """
    operands = instruction.operands
    result = int(cpu_context.registers.zf or cpu_context.registers.cf)
    logger.debug("Setting %s to 0x%X", operands[0].text, result)
    operands[0].value = result


@opcode
def SETLE(cpu_context: ProcessorContext, instruction: Instruction):
    """ Set if Less than or Equal """
    operands = instruction.operands
    result = int(cpu_context.registers.zf or (cpu_context.registers.sf != cpu_context.registers.of))
    logger.debug("Setting %s to 0x%X", operands[0].text, result)
    operands[0].value = result


@opcode
def SETGE(cpu_context: ProcessorContext, instruction: Instruction):
    """ Set if Greater than or Equal """
    operands = instruction.operands
    result = int(cpu_context.registers.sf == cpu_context.registers.of)
    logger.debug("Setting %s to 0x%X", operands[0].text, result)
    operands[0].value = result


@opcode
def SETG(cpu_context: ProcessorContext, instruction: Instruction):
    """ Set if Greather than """
    operands = instruction.operands
    result = int(cpu_context.registers.zf and (cpu_context.registers.sf == cpu_context.registers.of))
    logger.debug("Setting %s to 0x%X", operands[0].text, result)
    operands[0].value = result


@opcode
def SETE(cpu_context: ProcessorContext, instruction: Instruction):
    """ Set if Equal """
    operands = instruction.operands
    result = int(cpu_context.registers.zf)
    logger.debug("Setting %s to 0x%X", operands[0].text, result)
    operands[0].value = result
    # cpu_context.set_operand_value(0, result)


@opcode
def SETC(cpu_context: ProcessorContext, instruction: Instruction):
    """ Set if Carry """
    operands = instruction.operands
    result = int(cpu_context.registers.cf)
    logger.debug("Setting %s to 0x%X", operands[0].text, result)
    operands[0].value = result


@opcode
def SETBE(cpu_context: ProcessorContext, instruction: Instruction):
    """ Set if Below or Equal """
    operands = instruction.operands
    result = int(cpu_context.registers.cf and cpu_context.registers.zf)
    logger.debug("Setting %s to 0x%X", operands[0].text, result)
    operands[0].value = result


@opcode
def SETB(cpu_context: ProcessorContext, instruction: Instruction):
    """ Set if Below """
    SETC(cpu_context, instruction)


@opcode
def SETAE(cpu_context: ProcessorContext, instruction: Instruction):
    """ Set if Above or Equal """
    SETC(cpu_context, instruction)


@opcode
def SETA(cpu_context: ProcessorContext, instruction: Instruction):
    """ Set if Above """
    operands = instruction.operands
    result = int(not (cpu_context.registers.cf | cpu_context.registers.zf))
    logger.debug("Setting %s to 0x%X", operands[0].text, result)
    operands[0].value = result


@opcode
def SETPS(cpu_context: ProcessorContext, instruction: Instruction):
    """ Set if Not??? Parity """
    operands = instruction.operands
    result = int(cpu_context.registers.sf)
    logger.debug("Setting %s to 0x%X", operands[0].text, result)
    operands[0].value = result


@opcode("setp")
@opcode("setpe")
def setp(cpu_context: ProcessorContext, instruction: Instruction):
    """ Set if Parity """
    operands = instruction.operands
    result = int(cpu_context.registers.pf)
    logger.debug("Setting %s to 0x%X", operands[0].text, result)
    operands[0].value = result


@opcode("setnp")
@opcode("setpo")
def setnp(cpu_context: ProcessorContext, instruction: Instruction):
    """ Set if Not Parity """
    operands = instruction.operands
    result = int(not cpu_context.registers.pf)
    logger.debug("Setting %s to 0x%X", operands[0].text, result)
    operands[0].value = result


@opcode
def SETO(cpu_context: ProcessorContext, instruction: Instruction):
    """ Set if Overflow """
    operands = instruction.operands
    result = int(cpu_context.registers.of)
    logger.debug("Setting %s to 0x%X", operands[0].text, result)
    operands[0].value = result


@opcode
def SETNS(cpu_context: ProcessorContext, instruction: Instruction):
    """ Set if Not Sign """
    operands = instruction.operands
    result = int(not cpu_context.registers.sf)
    logger.debug("Setting %s to 0x%X", operands[0].text, result)
    operands[0].value = result


@opcode
def SETNO(cpu_context: ProcessorContext, instruction: Instruction):
    """ Set if Not Overflow """
    operands = instruction.operands
    result = int(not cpu_context.registers.of)
    logger.debug("Setting %s to 0x%X", operands[0].text, result)
    operands[0].value = result


@opcode
def SETNL(cpu_context: ProcessorContext, instruction: Instruction):
    """ Set if Not Less """
    operands = instruction.operands
    result = int(cpu_context.registers.sf == cpu_context.registers.of)
    logger.debug("Setting %s to 0x%X", operands[0].text, result)
    operands[0].value = result
    # cpu_context.set_operand_value(0, result)


@opcode
def SETNGE(cpu_context: ProcessorContext, instruction: Instruction):
    """ Set if Not Greater Than or Equal """
    operands = instruction.operands
    result = int(cpu_context.registers.sf != cpu_context.registers.of)
    logger.debug("Setting %s to 0x%X", operands[0].text, result)
    operands[0].value = result


@opcode
def SETNG(cpu_context: ProcessorContext, instruction: Instruction):
    """ Set if Not Greater """
    operands = instruction.operands
    result = int(cpu_context.registers.zf or (cpu_context.registers.sf != cpu_context.registers.of))
    logger.debug("Setting %s to 0x%X", operands[0].text, result)
    operands[0].value = result


@opcode
def SETNE(cpu_context: ProcessorContext, instruction: Instruction):
    """ Set if Not Equal """
    operands = instruction.operands
    result = int(not cpu_context.registers.zf)
    logger.debug("Setting %s to 0x%X", operands[0].text, result)
    operands[0].value = result


@opcode
def SETNC(cpu_context: ProcessorContext, instruction: Instruction):
    """ Set if Not Carry """
    operands = instruction.operands
    result = int(not cpu_context.registers.cf)
    logger.debug("Setting %s to 0x%X", operands[0].text, result)
    operands[0].value = result


@opcode
def SETNBE(cpu_context: ProcessorContext, instruction: Instruction):
    """ Set if Not Below or Equal """
    operands = instruction.operands
    result = int(not (cpu_context.registers.cf | cpu_context.registers.zf))
    logger.debug("Setting %s to 0x%X", operands[0].text, result)
    operands[0].value = result


@opcode
def SETNB(cpu_context: ProcessorContext, instruction: Instruction):
    """ Set if Not Below """
    SETNC(cpu_context, instruction)


@opcode
def SETNAE(cpu_context: ProcessorContext, instruction: Instruction):
    """ Set if Not Above or Equal """
    SETC(cpu_context, instruction)


@opcode
def SETL(cpu_context: ProcessorContext, instruction: Instruction):
    """ Set if Less Than """
    SETNGE(cpu_context, instruction)


@opcode
def SETNLE(cpu_context: ProcessorContext, instruction: Instruction):
    """ Set if Not Less Than or Equal """
    SETG(cpu_context, instruction)


@opcode
def SETNZ(cpu_context: ProcessorContext, instruction: Instruction):
    """ Set if Not Zero """
    SETNE(cpu_context, instruction)


@opcode
def SETZ(cpu_context: ProcessorContext, instruction: Instruction):
    """ Set if Zero """
    SETE(cpu_context, instruction)


@opcode
def SHR(cpu_context: ProcessorContext, instruction: Instruction):
    """ Shift Right """
    operands = instruction.operands
    opvalue1 = operands[0].value
    opvalue2 = operands[1].value
    width = get_max_operand_size(operands)

    if not opvalue2:
        return

    result = opvalue1
    tempcount = opvalue2 & (0x3F if cpu_context.bitness == 64 else 0x1F)
    while tempcount:
        cpu_context.registers.cf = get_lsb(result)
        result >>= 1
        tempcount -= 1

    cpu_context.registers.cf = (opvalue1 >> (opvalue2 - 1)) & 0x01
    cpu_context.registers.zf = int(result == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    if opvalue2 == 1:
        cpu_context.registers.of = utils.sign_bit(opvalue1, width)
    else:
        cpu_context.registers.of = 0

    cpu_context.registers.pf = get_parity(result)
    if cpu_context.emulator.branch_tracking:
        cpu_context.jcccontext.update_flag_opnds(["cf", "zf", "sf", "of", "pf"], operands)
    logger.debug("Shift 0x%X right by 0x%X -> 0x%X", opvalue1, opvalue2, result)
    operands[0].value = result


@opcode
def STD(cpu_context: ProcessorContext, instruction: Instruction):
    """ Set Direction Flag """
    cpu_context.registers.df = 1


@opcode
def STOSB(cpu_context: ProcessorContext, instruction: Instruction):
    """Store value in AL in the address pointed to by EDI"""
    value = cpu_context.registers.al
    addr = cpu_context.registers.edi
    logger.debug("Storing 0x%X into 0x%X", value, addr)
    cpu_context.memory.write(addr, bytes([value]))
    if cpu_context.registers.df:
        cpu_context.registers.edi -= 1
    else:
        cpu_context.registers.edi += 1


@opcode
def STOSW(cpu_context: ProcessorContext, instruction: Instruction):
    """Store value in AX in the address pointed to by EDI"""
    value = cpu_context.registers.ax
    addr = cpu_context.registers.edi
    logger.debug("Storing 0x%X into 0x%X", value, addr)
    cpu_context.memory.write(addr, value.to_bytes(2, cpu_context.byteorder))
    if cpu_context.registers.df:
        cpu_context.registers.edi -= 2
    else:
        cpu_context.registers.edi += 2


@opcode
def STOSD(cpu_context: ProcessorContext, instruction: Instruction):
    """Store value in EAX in the address pointed to by EDI"""
    value = cpu_context.registers.eax
    addr = cpu_context.registers.edi
    logger.debug("Storing 0x%X into 0x%X", value, addr)
    cpu_context.memory.write(addr, value.to_bytes(4, cpu_context.byteorder))
    if cpu_context.registers.df:
        cpu_context.registers.edi -= 4
    else:
        cpu_context.registers.edi += 4


@opcode
def STOSQ(cpu_context: ProcessorContext, instruction: Instruction):
    """Store value in RAX in the address pointed to by RDI"""
    value = cpu_context.registers.rax
    addr = cpu_context.registers.rdi
    logger.debug("Storing 0x%X into 0x%X", value, addr)
    cpu_context.memory.write(addr, value.to_bytes(8, cpu_context.byteorder))
    if cpu_context.registers.df:
        cpu_context.registers.rdi -= 8
    else:
        cpu_context.registers.rdi += 8


@opcode
def SUB(cpu_context: ProcessorContext, instruction: Instruction):
    """ Subtract """
    operands = instruction.operands
    opvalue1 = operands[0].value
    opvalue2 = operands[1].value
    width = get_max_operand_size(operands)
    result = opvalue1 - opvalue2

    mask = utils.get_mask(width)
    cpu_context.registers.cf = int((opvalue1 & mask) < (opvalue2 & mask))
    cpu_context.registers.af = int((opvalue1 ^ opvalue2 ^ result) & 0x10)
    cpu_context.registers.zf = int(result & mask == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = int(not (-(mask // 2) <= result < (mask // 2)))
    cpu_context.registers.pf = get_parity(result)
    if cpu_context.emulator.branch_tracking:
        cpu_context.jcccontext.update_flag_opnds(["cf", "af", "zf", "sf", "of", "pf"], operands)

    logger.debug("0x%X - 0x%X = 0x%X", opvalue1, opvalue2, result)
    operands[0].value = result


@opcode
def TEST(cpu_context: ProcessorContext, instruction: Instruction):
    """ Test values for equality """
    operands = instruction.operands
    opvalue1 = operands[0].value
    opvalue2 = operands[1].value
    width = get_max_operand_size(operands)
    result = opvalue1 & opvalue2

    mask = utils.get_mask(width)
    cpu_context.registers.cf = 0
    cpu_context.registers.af = int((opvalue1 ^ opvalue2 ^ result) & 0x10)
    cpu_context.registers.zf = int(result & mask == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = 0
    cpu_context.registers.pf = get_parity(result)
    if cpu_context.emulator.branch_tracking:
        cpu_context.jcccontext.update_flag_opnds(["cf", "af", "zf", "sf", "of", "pf"], operands)

    logger.debug("0x%X & 0x%X -> 0x%X", opvalue1, opvalue2, result)


@opcode
def XCHG(cpu_context: ProcessorContext, instruction: Instruction):
    """ Exchange two values """
    operands = instruction.operands
    opvalue1 = operands[0].value
    opvalue2 = operands[1].value
    logger.debug("exchange 0x%X and 0x%X", opvalue1, opvalue2)
    operands[1].value = opvalue1
    operands[0].value = opvalue2


@opcode("xor")
@opcode("pxor")
def _xor(cpu_context: ProcessorContext, instruction: Instruction):
    """ XOR """
    operands = instruction.operands
    opvalue1 = operands[0].value
    opvalue2 = operands[1].value
    width = get_max_operand_size(operands)
    result = opvalue1 ^ opvalue2

    cpu_context.registers.cf = 0
    cpu_context.registers.zf = int(result == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = 0
    cpu_context.registers.pf = get_parity(result)
    if cpu_context.emulator.branch_tracking:
        cpu_context.jcccontext.update_flag_opnds(["cf", "zf", "sf", "of", "pf"], operands)

    logger.debug("0x%X ^ 0x%X = 0x%X", opvalue1, opvalue2, result)
    operands[0].value = result


# Global helper functions


def get_max_operand_size(operands):
    """
    Given the list of named tuples containing the operand value and bit width, determine the largest bit width.

    :param operands: list of Operand objects

    :return: largest operand width
    """
    return max(operand.width for operand in operands)


def get_min_operand_size(operands):
    """
    Given the list of named tuples containing the operand value and bit width, determine the smallest bit width.

    :param operands: list of Operand objects

    :return: smallest operand width
    """
    return min(operand.width for operand in operands)


def get_msb(value, size):
    """
    Get most significant bit.

    :param value: value to obtain msb from
    :param size: bit width of value in bytes

    :return: most significant bit
    :raises AssertionError: value is larger than given size.
    """
    msb = value >> ((8 * size) - 1)
    if msb > 1:
        raise AssertionError(f"Got invalid size {size} for value 0x{value:x}")
    return msb


def get_lsb(value):
    """
    Get least significant bit.

    :param value: value to obtain lsb from

    :return: least significant bit
    """
    return value & 0x1


def swap_bytes(value, size):
    """
    Swaps a set of bytes based on size

    :param value: value to swap

    :param size: width of value in bytes

    :return: swapped
    """
    if size == 1:
        return value

    if size == 2:
        return ((value & 0xFF) << 8) | ((value & 0xFF00) >> 8)

    if size == 4:
        return (
            ((value & 0xFF) << 24)
            | (((value & 0xFF00) >> 8) << 16)
            | (((value & 0xFF0000) >> 16) << 8)
            | ((value & 0xFF000000) >> 24)
        )

    if size == 8:
        return (
            ((value & 0xFF) << 56)
            | (((value & 0xFF00) >> 8) << 48)
            | (((value & 0xFF0000) >> 16) << 40)
            | (((value & 0xFF000000) >> 24) << 32)
            | (((value & 0xFF00000000) >> 32) << 24)
            | (((value & 0xFF0000000000) >> 40) << 16)
            | (((value & 0xFF000000000000) >> 48) << 8)
            | ((value & 0xFF00000000000000) >> 56)
        )


# fmt: off
parity_lookup_table = [
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
]
# fmt: on


def get_parity(value):
    """Returns the parity of the given value."""
    return parity_lookup_table[value & 0xFF]
