# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
Provides a more functional way of accessing the fields from Capstone's
CsInsn instructions.

NOTES
-----
This library assumes that the AT & T is the syntax used.
We try to accommodate Intel syntax by checking where necessary. Fortunately,
capstone includes a reference to the disassembler on each instruction, thus allowing
to check the syntax in use, at runtime.
"""

import capstone
import re
from capstone import x86
from capstone import x86_const

from functools import wraps

# Used to negate assertion functions
RE_NOT = re.compile(r'((^not_)|(_not$)|(_not_))')

# --- helper functions
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


def _warn(message):
    print "[WARN] {}".format(message)

# --- library functions

# Assertion definitions
def assert_single_operand(insn):
    assert len(insn.operands) == 1

class _matchers:
    """
    Container for higher-order functions that build string matching functions.
    """
    def startswith(self, what): return lambda s: s.startswith(what)

    def endswith(self, what): return lambda s: s.endswith(what)

    def contains(self, what): return lambda s: s.contains(what)


_matchers = _matchers()


def any_yields(functions, value):
    """Do any of the functions resolve to true when applied to `value`?"""
    return any(f(value) for f in functions)


def _not_assert(function):
    """Flip a function that raises an assertion"""
    @wraps(function)
    def flipped(*args, **kwargs):
        try:
            function(*args, **kwargs)
            raise AssertionError()
        except AssertionError:
            return
    return flipped


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
            # support for negating assertion functions
            if match.group(1) == '_not_':
                # not in the middle as in `is_not_memory`
                func = RE_NOT.sub('_', item)
            else:
                # not at the beginning or end as in `not_is_memory` or `is_memory_not` 
                func = RE_NOT.sub('', item)
            # check whether the function exists
            if not hasattr(self, func):
                raise AttributeError("Cannot negate non-existing function: {}".format(func))
            else:
                return _not_assert(getattr(self, func))
        raise AttributeError("Field not found: " + str(item))


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

    def sib_registers(self, csinsn, operand, as_strings=False):
        regs = set()
        if self.is_memory(operand):
            regs.add(operand.value.mem.base)
            regs.add(operand.value.mem.index)

        regs = regs - set([None])  # Remove None if one of the values were None

        if as_strings:
            regs = set([register.to_string(csinsn, operand)])

        return regs

    def registers(self, csinsn, operand, as_string=True):
        operand = ensure.not_none(operand)
        regs = set()
        if self.is_memory(operand):
            regs.add(operand.value.mem.base)
            regs.add(operand.value.mem.index)
        elif self.is_register(operand):
            regs.add(operand.value.reg)

        regs = regs - set([None])  # Remove None if one of the values were None

        if as_string:
            regs = set([register.to_string(csinsn, operand)])

        return regs


# set of functions that operate over all the operands of an instruction
class operands(object):
    def _register_iterable_to_string(self, insn, registers):
        return [insn.reg_name(_) for _ in registers]

    def canonically_ordered(self, insn, as_strings=False):
        """
        Orders the operands in the AT&T style, thus
        the form we use is insn needle, haystack
        """
        if disassembler.is_syntax_att(insn):
            ops = list(insn.operands)
        elif disassembler.is_syntax_intel(insn):
            ops = list(reversed(insn.operands))

        if as_strings:
            ops = [_ for _ in ops]
        return ops

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


class fetch(object):
    def only_operand(self, insn):
        ensure.is_capstone_insn(insn)
        if ensure.not_none(insn.op_count) == 1:
            raise ValueError("op count for instruction `{}` != 1".format(insn))
        return insn.operands[0]


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


class write_to(object):
    _memory_mnemonics = (
        _matchers.startswith('push'),
    )
    _not_memory_mnemonics = (
        _matchers.startswith('nop'),
        _matchers.startswith('jmp'),
    )

    def memory(self, insn):
        # FIXME Assume for now that we write to memory if the last parameter is a memory operand
        ensure.is_capstone_insn(insn)
        ops = operands.canonically_ordered(insn)

        is_memop = lambda: len(ops) > 0 and ops[-1].type == capstone.CS_OP_MEM
        is_excluded = lambda: any_yields(self._not_memory_mnemonics, mnemonic(insn))
        is_included = lambda: any_yields(self._memory_mnemonics, mnemonic(insn))

        # is the last operand a memory operand?
        # ASS. It's more likely that a write to memory will have at least two arguments
        # This is obviously not true for all instructions, consider PUSH %rax
        is_memory = is_included() or (is_memop() and not is_excluded())

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


class read_from(object):
    def memory(self, insn):
        ensure.is_capstone_insn(insn)
        ops = operands.canonically_ordered(insn)

        # XXX This makes the dubious assumption:
        #     All instructions that read from memory, 
        #     have the address as leftmost operand
        #
        # We should rather consider the actual instruction encodings from the intel manual
        # to fully understand which instructions actually read from memory.

        if len(ops) == 0:
            return False
        else:
            return ops[0].type == capstone.CS_OP_MEM

    def register(self, insn, ignore=frozenset(), ignore_sib=False):
        """
        Does this instruction read from a a register?

        Parameters
        ----------
        insn: capstone.CsInsn
            The assembly instruction

        ignore: set
            Which registers are we to ignore?
        """
        ensure.is_capstone_insn(insn)

        if ignore_sib:
            ops = operands.canonically_ordered(insn)
            ignore = set(ignore)
            for o in ops:
                ignore.update(operand.sib_registers(insn, o))

        reads = set(operands.registers_read(insn, as_strings=False))
        reads = reads - ignore
        return len(reads) > 0


class register(object):
    def to_string(self, csinsn, register):
        ensure.is_capstone_insn(csinsn)
        return csinsn.reg_name(register)


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


def mnemonic(insn):
    return insn.mnemonic


def opstring(insn):
    return insn.op_str


def string(insn):
    return str(insn)


# dynamic Instantiation of all the classes
_classes = [
    disassembler,
    ensure,
    operand,
    operands,
    fetch,
    branch,
    write_to,
    read_from,
    register
]

for cls in _classes:
    globals()[cls.__name__] = cls()
