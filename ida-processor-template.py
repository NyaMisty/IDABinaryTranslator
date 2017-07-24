# coding=utf-8

#import pydevd
#pydevd.settrace('localhost', port=15306, stdoutToServer=True, stderrToServer=True,suspend=False,overwrite_prev_trace=True,patch_multiprocessing=True)

from idaapi import *
from idc import *
import idautils
import copy
import ctypes

def SIGNEXT(x, b):
    m = 1 << (b - 1)
    m = 1 << (b - 1)
    x = x & ((1 << b) - 1)
    return (x ^ m) - m

def toInt(x):
    return ctypes.c_int(x & 0xffffffff).value

FL_B = 0x000000001  # 8 bits
FL_W = 0x000000002  # 16 bits
FL_D = 0x000000004  # 32 bits
FL_Q = 0x000000008  # 64 bits
FL_OP1 = 0x000000010  # check operand 1
FL_32 = 0x000000020  # Is 32
FL_64 = 0x000000040  # Is 64
FL_NATIVE = 0x000000080  # native call (not EbcCal)
FL_REL = 0x000000100  # relative address
FL_CS = 0x000000200  # Condition flag is set
FL_NCS = 0x000000400  # Condition flag is not set
FL_INDIRECT = 0x000000800  # This is an indirect access (not immediate value)
FL_SIGNED = 0x000001000  # This is a signed operand

FL_ABSOLUTE = 1  # absolute: &addr
FL_SYMBOLIC = 2  # symbolic: addr

PR_TINFO = 0x20000000  # not present in python??

if __EA64__:
    EA_BITMASK = 0xffffffffffffffff
else:
    EA_BITMASK = 0xffffffff

class DecodingError(Exception):
    pass

class openrisc_processor_hook_t(IDP_Hooks):
    def __init__(self):
        IDP_Hooks.__init__(self)

    def decorate_name3(self, name, mangle, cc):
        gen_decorate_name3(name, mangle, cc)
        return name

    def calc_retloc3(self, rettype, cc, retloc):
        if not rettype.is_void():
            retloc._set_reg1(10)
        return 1

    def calc_varglocs3(self, ftd, regs, stkargs, nfixed):
        return 1

    def calc_arglocs3(self, fti):
        self.calc_retloc3(fti.rettype, 0, fti.retloc)
        n = fti.size()
        for i in xrange(0, n):
            if i > 7:
                return -1
            fti[i].argloc.set_reg1(10 + i, 0)
        fti.stkargs = 0
        return 2

    def use_stkarg_type3(self, ea, arg):
        return 0

    def use_regarg_type3(self, ea, rargs):
        length = decode_insn(ea)
        if length <= 0:
            return -1
        ft = cmd.get_canon_feature()
        regList = []
        n = rargs.size()
        idx = -1
        if n is None or n < 0:
            return 2
        for i in xrange(0, n):
            regList.append(rargs[i].argloc.reg1())
        if ft & CF_USE1 and cmd[0].type == o_reg:
            if cmd[0].reg in regList:
                idx = cmd[0].reg
                if ft & CF_CHG1:
                    idx |= REG_SPOIL
                return idx
        if ft & CF_USE2 and cmd[1].type == o_reg:
            if cmd[1].reg in regList:
                idx = cmd[1].reg
                if ft & CF_CHG2:
                    idx |= REG_SPOIL
                return idx
        if ft & CF_USE3 and cmd[2].type == o_reg:
            if cmd[2].reg in regList:
                idx = cmd[2].reg
                if ft & CF_CHG3:
                    idx |= REG_SPOIL
                return idx
        if ft & CF_USE4 and cmd[3].type == o_reg:
            if cmd[3].reg in regList:
                idx = cmd[3].reg
                if ft & CF_CHG4:
                    idx |= REG_SPOIL
                return idx
        return idx

    def use_arg_types3(self, ea, fti, rargs):
        gen_use_arg_tinfos(ea, fti, rargs)
        return 2

    def calc_purged_bytes3(self, p_purged_bytes, fti):
        p_purged_bytes = 0
        return 2


class openrisc_processor_t(processor_t):
    # id = 0x8001 + 0x5571C
    id = 243
    flag = PR_SEGS | PRN_HEX | PR_RNAMESOK | PR_NO_SEGMOVE | PR_TINFO | PR_TYPEINFO
    #flag = PR_SEGS | PRN_HEX | PR_RNAMESOK | PR_NO_SEGMOVE
    cnbits = 8
    dnbits = 8
    author = "Deva & Misty"
    psnames = ["RISC-V"]
    plnames = ["RISC-V"]
    segreg_size = 0
    instruc_start = 0
    assembler = {
        "flag": ASH_HEXF0 | ASD_DECF0 | ASO_OCTF5 | ASB_BINF0 | AS_N2CHR,
        "uflag": 0,
        "name": "RISC-V asm",
        "origin": ".org",
        "end": ".end",
        "cmnt": ";",
        "ascsep": '"',
        "accsep": "'",
        "esccodes": "\"'",
        "a_ascii": ".ascii",
        "a_byte": ".byte",
        "a_word": ".word",
        "a_dword": ".dword",
        "a_qword": ".qword",
        "a_bss": "dfs %s",
        "a_seg": "seg",
        "a_curip": "PC",
        "a_public": "",
        "a_weak": "",
        "a_extrn": ".extern",
        "a_comdef": "",
        "a_align": ".align",
        "lbrace": "(",
        "rbrace": ")",
        "a_mod": "%",
        "a_band": "&",
        "a_bor": "|",
        "a_xor": "^",
        "a_bnot": "~",
        "a_shl": "<<",
        "a_shr": ">>",
        "a_sizeof_fmt": "size %s",
    }

    reg_names = regNames = [
        # 在这里填上寄存器的顺序
        # 记得也要留着下面的两行哦
        # virtual
        "CS", "DS"
    ]

    instruc = instrs = [#{'name': 'lui', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'lui rd,imm'},
                        # 在这里按照上面的格式添加指令~~
                        ]

    instruc_end = len(instruc)
    idphook = None

    def __init__(self):
        processor_t.__init__(self)
        self._init_instructions()
        self._init_registers()
        self.last_lui_array = [{'reg': -1, 'value': 0}]

    def _init_instructions(self):
        self.inames = {}
        for idx, ins in enumerate(self.instrs):
            self.inames[ins['name']] = idx

    def _init_registers(self):
        self.reg_ids = {}
        for i, reg in enumerate(self.reg_names):
            self.reg_ids[reg] = i
        self.regFirstSreg = self.regCodeSreg = self.reg_ids["CS"]
        self.regLastSreg = self.regDataSreg = self.reg_ids["DS"]

    def _read_cmd_dword(self):
        ea = self.cmd.ea + self.cmd.size
        dword = get_full_long(ea)
        self.cmd.size += 4
        return dword

    def _ana(self):
        cmd = self.cmd
        # ua_next_dword() is also ok :)
        opcode = self._read_cmd_dword()
        # 如果解析出错的话就raise这个exception，一般是像下面这样用
        # if ...... decode inst1
        # if ...... decode inst2
        # ....... decode.....
        # else:
        #    raise DecodingError()
        return cmd.size

    def ana(self):
        try:
            return self._ana()
        except DecodingError:
            return 0

    def _emu_operand(self, op):
        if op.type == o_mem:
            ua_dodata2(0, op.addr, op.dtyp)
            ua_add_dref(0, op.addr, dr_R)
        elif op.type == o_near:
            if self.cmd.get_canon_feature() & CF_CALL:
                fl = fl_CN
            else:
                fl = fl_JN
            ua_add_cref(0, op.addr, fl)

    #这三个是下面simplify的辅助函数可以看看供为参考
    def remove_lui_array_object(self, reg):
        ret = None
        # print "remove_lui_array_object: %s" % (self.regNames[reg])
        for idx, lui_record in enumerate(self.last_lui_array):
            if lui_record is None:
                continue
            if lui_record["reg"] is None:
                del self.last_lui_array[idx]
            elif lui_record["reg"] == reg:
                ret = copy.deepcopy(lui_record)
                del self.last_lui_array[idx]
        return ret

    def get_lui_array_object(self, reg):
        ret = None
        # print "get_lui_array_object: %s" % (self.regNames[reg])
        for idx, lui_record in enumerate(self.last_lui_array):
            if lui_record is None:
                continue
            if lui_record["reg"] is None:
                del self.last_lui_array[idx]
            elif lui_record["reg"] == reg:
                ret = lui_record
        return ret

    def add_auto_resolved_address_comment(self, resolved_offset):
        buf = init_output_buffer(1024)
        r = out_name_expr(self.cmd, resolved_offset, BADADDR)
        if not r:
            OutLong(toInt(resolved_offset) & EA_BITMASK, 16)
        term_output_buffer()
        MakeComm(self.cmd.ea, buf)
        nn = netnode("$ simplified_addr",0,True)
        nn.altset(self.cmd.ea,resolved_offset & EA_BITMASK)
        pass

    def add_auto_resolved_constant_comment(self, resolved_offset):
        buf = init_output_buffer(1024)
        r = out_name_expr(self.cmd, resolved_offset, BADADDR)
        if not r:
            OutLong(toInt(resolved_offset) & EA_BITMASK, 16)
        term_output_buffer()
        MakeComm(self.cmd.ea, buf)
        nn = netnode("$ simplified_const", 0, True)
        nn.altset(self.cmd.ea, resolved_offset & EA_BITMASK)
        pass

    # lui            a0, 65536
    # addi           a0, a0, 320
    # add data and far call offset
    #这里是简单的化简 供参考用
    def simplify(self):
        if self.cmd.itype == self.inames['lui']:
            # print "lui at: %08X on reg %s value %Xh\n" % (self.cmd.ea, self.regNames[self.cmd[0].reg], self.cmd[1].value)
            self.remove_lui_array_object(self.cmd[0].reg)
            self.remove_auipc_array_object(self.cmd[0].reg)
            self.last_lui_array.append({"reg": self.cmd[0].reg, "value": self.cmd[1].value})
            return
        elif self.cmd.itype == self.inames['ld'] or self.cmd.itype == self.inames['lw'] \
                or self.cmd.itype == self.inames['lh'] or self.cmd.itype == self.inames['lb'] \
                or self.cmd.itype == self.inames['ldu'] or self.cmd.itype == self.inames['lwu'] \
                or self.cmd.itype == self.inames['lhu'] or self.cmd.itype == self.inames['lbu']:
            last_record_lui = self.get_lui_array_object(self.cmd[1].reg)
            self.remove_lui_array_object(self.cmd[0].reg)
            if last_record_lui != None:
                target_offset = toInt((last_record_lui["value"] << 12) + self.cmd[1].addr)
                if (isLoaded(target_offset)):
                    ua_add_dref(0, target_offset, dr_R)
                self.add_auto_resolved_constant_comment(target_offset)
        elif self.cmd[1].reg != None:
            cmd = self.cmd
            ft = cmd.get_canon_feature()
            if ft & CF_CHG1:
                last_record_lui = self.get_lui_array_object(self.cmd[1].reg)
                self.remove_lui_array_object(self.cmd[0].reg)
                if last_record_lui != None:
                    # print "trying to match addi or jalr for lui, cur ea: %08X" % (self.cmd.ea)
                    if self.cmd.itype == self.inames['addi']:
                        target_offset = toInt((last_record_lui["value"] << 12) + self.cmd[2].value)
                        if (isLoaded(target_offset)):
                            ua_add_dref(0, target_offset, dr_R)
                        self.add_auto_resolved_constant_comment(target_offset)
                    elif self.cmd.itype == self.inames['jalr']:
                        if self.cmd[0].reg == 1 and self.cmd[1].reg == 1:
                            return
                        target_offset = toInt((last_record_lui["value"] << 12) + self.cmd[2].value)
                        if (isLoaded(target_offset)):
                            ua_add_cref(0, target_offset, fl_JN)
                        self.add_auto_resolved_constant_comment(target_offset)
    #这个函数不用动哒
    def add_stkpnt(self, pfn, v):
        if pfn:
            end = self.cmd.ea + self.cmd.size
            if not is_fixed_spd(end):
                AddAutoStkPnt2(pfn, end, v)

    #这里处理会修改sp的指令，如果懒or时间不够的话就留空吧
    def trace_sp(self):
        """
        Trace the value of the SP and create an SP change point if the current
        instruction modifies the SP.
        """
        # pfn = get_func(self.cmd.ea)
        # if not pfn:
        #    return
        if self.cmd[0].reg != None and self.cmd[0].reg == 2 and self.cmd[1].reg != None and self.cmd[1].reg == 2 and \
                        self.cmd.itype in [self.inames['addi'], self.inames['addid'], self.inames['addiw']]:
            # print self.cmd[2].value
            spofs = toInt(self.cmd[2].value)
            # print spofs
            self.add_stkpnt(self.cmd.ea, spofs)

    def emu(self):
        cmd = self.cmd
        # 下面的全是套路，flow是该指令是否将控制流传给下一条相邻指令的意思
        flow = False

        # 首先对特殊指令做处理
        if cmd.itype == self.inames['jal']:
            # 无条件跳转 类似于x86 jmp
            if cmd[0].reg == 0:
                flow = False
                ua_add_cref(0, cmd[1].addr, fl_JN)
            # 带link跳转 类似于x86 call
            if cmd[0].reg == 1:
                flow = True
                ua_add_cref(0, cmd[1].addr, fl_CN)
                ua_add_cref(0, cmd.ea + cmd.size, fl_F)
            # 其他情况
            elif cmd[0].reg != 0:
                ua_add_cref(0, cmd.ea + cmd.size, fl_F)
                flow = True
            pass
        elif cmd.itype == self.inames['jalr']:
            # 无条件跳转
            if cmd[0].reg == 0:
                flow = False
            # 中间文件的用于重定位占位的特殊情况
            elif cmd[0].reg == 1 and cmd[1].reg == 1 and cmd[1].addr == 0:
                flow = True
            # 跳转至link 相当于retn
            elif cmd[1].reg == 1 and cmd[1].addr == 0:
                flow = False
            # 子函数调用 相当于call
            elif cmd[0].reg == 1:
                flow = True
                ua_add_cref(0, cmd.ea + cmd.size, fl_F)
                try:
                    nn = netnode("$ simplified_addr", 0, False)
                    if nn == BADNODE:
                        raise Exception("Resolved addr not found")
                    target = nn.altval(self.cmd.ea)
                    ua_add_cref(0, target, fl_CN)
                except:
                    print "Error while making function from cmd.ea:0x%X" % (cmd.ea)
            else:
                flow = False
        else:
            # 其他指令正常处理
            ft = cmd.get_canon_feature()
            if ft & CF_USE1:
                self._emu_operand(cmd[0])
            if ft & CF_USE2:
                self._emu_operand(cmd[1])
            if ft & CF_USE3:
                self._emu_operand(cmd[2])
            if ft & CF_USE4:
                self._emu_operand(cmd[3])

            elif not ft & CF_STOP:
                ua_add_cref(0, cmd.ea + cmd.size, fl_F)
                flow = True
        self.simplify()
        # trace the stack pointer if:
        #   - it is the second analysis pass
        #   - the stack pointer tracing is allowed
        if may_trace_sp():
            if flow:
                self.trace_sp()  # trace modification of SP register
            else:
                recalc_spd(self.cmd.ea)  # recalculate SP register for the next insn
        return True

    # 剩下的这两个函数全是基本固定的 等出问题再说
    def outop(self, op):
        optype = op.type
        fl = op.specval

        if optype == o_reg:
            out_register(self.regNames[op.reg])

        elif optype == o_imm:
            OutValue(op, OOFW_IMM | OOFW_32 | OOF_SIGNED)

        elif optype in [o_near, o_mem]:
            if optype == o_mem and fl == FL_ABSOLUTE:
                out_symbol('&')
            r = out_name_expr(op, op.addr, BADADDR)
            if not r:
                out_tagon(COLOR_ERROR)
                out_tagon(COLOR_ERROR)
                OutLong(op.addr, 16)
                out_tagoff(COLOR_ERROR)
                QueueSet(Q_noName, self.cmd.ea)
                # OutLong(op.addr, 16)

        elif optype == o_displ:
            if fl & FL_INDIRECT:
                out_symbol('[')
            out_register(self.regNames[op.reg])

            OutValue(op, OOF_ADDR | OOFW_32 | OOFS_NEEDSIGN | OOF_SIGNED)

            if fl & FL_INDIRECT:
                out_symbol(']')

        elif optype == o_phrase:
            out_symbol('@')
            out_register(self.regNames[op.reg])
        else:
            return False

        return True

    def out(self):
        cmd = self.cmd
        ft = cmd.get_canon_feature()
        buf = init_output_buffer(1024)
        OutMnem(15)
        if ft & CF_USE1:
            out_one_operand(0)
        if ft & CF_USE2:
            OutChar(',')
            OutChar(' ')
            out_one_operand(1)
        if ft & CF_USE3:
            OutChar(',')
            OutChar(' ')
            out_one_operand(2)
        term_output_buffer()
        cvar.gl_comm = 1
        MakeLine(buf)

    def notify_init(self,idp_file):
        try:
            idp_hook_stat = "un"
            print "IDP hook: checking for hook..."
            self.idphook
            print "IDP hook: unhooking...."
            self.idphook.unhook()
            self.idphook = None
        except:
            print "IDP hook: not installed, installing now...."
            idp_hook_stat = ""
            self.idphook = openrisc_processor_hook_t()
            self.idphook.hook()
        #cvar.inf.mf = LITTLE_ENDIAN
        return True

    def notify_term(self):
        try:
            idp_hook_stat = "un"
            print "IDP hook: checking for hook..."
            self.idphook
            print "IDP hook: unhooking...."
            self.idphook.unhook()
            self.idphook = None
        except:
            pass

    # 处理是否是call指令（其实没什么用- -
    # 返回<=0不是，返回2是，返回1不知道
    def notify_is_call_insn(self, ea):
        cmd = self.cmd
        if cmd.itype == self.inames['jal']:
            if cmd[0].reg == 0:
                return 0
            elif cmd[0].reg == 1:
                return 2
            else:
                return 1
            pass
        elif cmd.itype == self.inames['jalr']:
            if cmd[0].reg == 0:
                return 0
            elif cmd[1].reg == 1 and cmd[1].addr == 0:
                return 0
            elif cmd[0].reg == 1:
                return 2
            else:
                return 1

def PROCESSOR_ENTRY():
    return openrisc_processor_t()
