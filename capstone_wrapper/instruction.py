"""
    Library that implements a more functional way of accessing the fields capstone's
    CsInsn instructions.
"""

import capstone
import re
from capstone import x86
from capstone import x86_const

# Used to negate assertion functions
RE_NOT = re.compile(r'((^not_)|(_not$)|(_not_))')

# This library assumes that the AT & T is the syntax used
# We try to accommodate intel by checking where necessary,
# luckily capstone includes a reference to the disassembler on each instruction which allows us
# to check the syntax at runtime

# Assertion definitions
def assert_single_operand(insn):
    assert len(insn.operands) == 1


def _warn(message):
    print "[WARN] {}".format(message)


def expect_capstone_at_least_version(expected):
    if isinstance(expected, tuple):
        expected = list(expected)
    else:
        expected = list(expected.split('.'))
    actual = list(capstone.__version__.split('.'))
    l = max(len(expected), len(actual))

    expected += [0] * (l - len(expected))
    actual += [0] * (l - len(actual))

    if actual < expected:
        actual = '.'.join(actual)
        expected = '.'.join(expected)
        raise AssertionError("Capstone version {} < {}".format(actual, expected))


def _not_assert(function):
    """Flip a function that raises an assert assert"""

    def _(*args, **kwargs):
        try:
            function(*args, **kwargs)
            raise AssertionError()
        except AssertionError:
            return

    return _


class disassembler(object):
    def ensure_disassembler(self, obj):
        """Ensures that the object is a capstone.Cs instance,
        if not, it attempts to make it into one, or raises an error"""
        if isinstance(obj, capstone.Cs):
            return obj
        elif isinstance(obj, capstone.CsInsn):
            # XXX Do recursive to ensure that the checking occurs always
            return self.ensure_disassembler(obj._cs)
        else:
            raise ValueError(
                    "Expected either instruction or disassembler instance as parameter, but got: {}".format(repr(obj))
            )

    def is_syntax_att(self, obj):
        obj = self.ensure_disassembler(obj)
        return obj.syntax == capstone.CS_OPT_SYNTAX_ATT

    def is_syntax_intel(self, obj):
        obj = self.ensure_disassembler(obj)
        return obj.syntax == capstone.CS_OPT_SYNTAX_INTEL


disassembler = disassembler()


class ensure(object):
    """
    Several methods for sanity checks, used during development
    """

    def has_single_operand(self, instruction):
        assert len(instruction.operands) == 1

    def is_capstone_insn(self, insn):
        assert insn is not None
        assert isinstance(insn, capstone.CsInsn)

    def is_jump(self, insn):
        assert capstone.CS_GRP_JUMP in insn.groups

    def is_call(self, insn):
        assert capstone.CS_GRP_CALL in insn.groups

    def is_branch(self, insn):
        assert (capstone.CS_GRP_JUMP in insn.groups) or (capstone.CS_GRP_CALL in insn.groups)

    def is_unconditional_jump(self, insn):
        mnemonic = insn.mnemonic.lower()
        assert mnemonic.startswith('jmp')
        assert x86_const.X86_REG_EFLAGS not in insn.regs_read

    def not_none(self, something):
        assert something is not None
        return something

    def __getattr__(self, item):
        match = RE_NOT.match(item)
        if match:
            """Allows for negating assertions"""
            if match.group(1) == '_not_':
                func = RE_NOT.sub('_', item)
            else:
                func = RE_NOT.sub('', item)
            # check whether the function exists
            if not hasattr(self, func):
                raise AttributeError("Cannot negate non-existing function: {}".format(func))
            else:
                return _not_assert(getattr(self, func))
        raise AttributeError("Field not found: " + str(item))


ensure = ensure()


# operand specific functions
class operand(object):
    def is_memory(self, operand):
        return ensure.not_none(operand.type) == capstone.CS_OP_MEM

    def is_register(self, operand):
        return ensure.not_none(operand.type) == capstone.CS_OP_REG

    def is_immediate(self, operand):
        return ensure.not_none(operand.type) == capstone.CS_OP_IMM

    def as_immediate(self, operand):
        return operand.value.imm


operand = operand()


# set of functions that operate over all the operands of an instruction
class operands(object):
    def _register_iterable_to_string(self, insn, registers):
        return [insn.reg_name(_) for _ in registers]

    def canonically_ordered(self, insn):
        if disassembler.is_syntax_att(insn):
            return list(insn.operands)
        elif disassembler.is_syntax_intel(insn):
            return list(reversed(insn.operands))

    def registers_read_implicit(self, insn):
        ensure.is_capstone_insn(insn)
        return set(insn.regs_read)

    def registers_write_implicit(self, insn):
        ensure.is_capstone_insn(insn)
        return set(insn.regs_write)

    def registers_read_explicit(self, insn):
        expect_capstone_at_least_version('4.0')
        ensure.is_capstone_insn(insn)

        read, _ = insn.regs_access()
        read = set(read) - set(insn.regs_read)
        return read

    def registers_write_explicit(self, insn):
        expect_capstone_at_least_version('4.0')
        ensure.is_capstone_insn(insn)

        _, write = insn.regs_access()
        read = set(write) - set(insn.regs_write)
        return read

    def registers_read(self, insn, as_strings=True, include_implicit=True):
        expect_capstone_at_least_version('4.0')
        ensure.is_capstone_insn(insn)

        # XXX assume for now x86 registers
        if include_implicit:
            read, _ = insn.regs_access()
        else:
            read = self.registers_read_explicit(insn)

        if not as_strings:
            return list(read)
        else:
            return [insn.reg_name(_) for _ in read]

    def registers_write(self, insn, as_strings=True, include_implicit=True):
        expect_capstone_at_least_version('4.0')
        ensure.is_capstone_insn(insn)
        _, write = insn.regs_access()

        if include_implicit:
            _, write = insn.regs_access()
        else:
            write = self.registers_write_explicit(insn)

        if not as_strings:
            return list(write)
        else:
            return [insn.reg_name(_) for _ in write]


operands = operands()


class fetch(object):
    def only_operand(self, insn):
        ensure.is_capstone_insn(insn)
        if ensure.not_none(insn.op_count) == 1:
            raise ValueError("op count for instruction `{}` != 1".format(insn))
        return insn.operands[0]


fetch = fetch()


# FIXME add support for loopnz/ne and loopz/e
class branch(object):
    def is_unconditional(self, insn):
        ensure.is_capstone_insn(insn)
        ensure.is_branch(insn)
        # if the register is read, then a decision is made
        # based on some condition
        if x86_const.X86_REG_EFLAGS in insn.regs_read:
            ensure.not_is_unconditional_jump(insn)
            return False

        return operand.is_immediate(fetch.only_operand(insn))

    def is_conditional(self, insn):
        ensure.is_capstone_insn(insn)
        ensure.is_branch(insn)
        return operand.is_memory(fetch.only_operand(insn)) or operand.is_register(fetch.only_operand(insn))

    def is_indirect(self, insn):
        ensure.is_capstone_insn(insn)
        ensure.is_branch(insn)

        return operand.is_memory(fetch.only_operand(insn)) or operand.is_register(fetch.only_operand(insn))


branch = branch()


class writes_to(object):
    def memory(self, insn):
        # FIXME Assume for now that we write to memory if the last parameter is a memory operand
        ensure.is_capstone_insn(insn)
        ops = operands.canonically_ordered(insn)

        is_memory = len(ops) > 0 and ops[-1].type == capstone.CS_OP_MEM

        if self.register(insn) and is_memory:
            _warn("INSN[{} {}] writes to memory and registers({})".format(
                    insn.mnemonic,
                    insn.op_str,
                    operands.registers_write(insn)))
        return is_memory

    def register(self, insn, ignore=frozenset()):
        ensure.is_capstone_insn(insn)
        writes = set(operands.registers_write(insn, as_strings=False))
        writes = writes - ignore
        return len(writes) > 0


writes_to = writes_to()


# Some general instruction specific checks
def is_jump(insn):
    ensure.is_capstone_insn(insn)
    return capstone.CS_GRP_JUMP in insn.groups


def is_call(insn):
    ensure.is_capstone_insn(insn)
    return capstone.CS_GRP_CALL in insn.groups


def is_invalid(insn):
    return capstone.CS_GRP_INVALID in insn.groups


def is_return(insn):
    is_return = capstone.CS_GRP_IRET in insn.groups
    is_return = is_return or capstone.CS_GRP_RET in insn.groups
    return is_return
