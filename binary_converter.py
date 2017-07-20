# coding=utf-8

import pydevd
pydevd.settrace('localhost', port=15306, stdoutToServer=True, stderrToServer=True)

from idaapi import *
from idc import *
from idautils import *
import traceback

class NoCorrespondingRegError(Exception):
    pass

class UnsupportedCornerCase(Exception):
    pass

class openrisc_translator_arm:
    f = None
    isCurInData = False
    xlen = 4
    def __init__(self,name):
        self.f = open(name,"w")

    def out(self, buf):
        if not self.f is None:
            self.f.write(buf + "\n")

    def printAsmHeader(self):
        pass

    def printAsmFooter(self):
        self.out("  END")
        pass

    def printSegHeader(self,ea,attr):
        segHeader = "   AREA     "
        segHeader += SegName(ea)
        segHeader += ", "
        if attr & SEGPERM_EXEC:
            segHeader += "CODE, "
        else:
            segHeader += "DATA, "
        if not isLoaded(ea):
            segHeader += "NOINIT, "
        if attr & SEGPERM_READ and attr & SEGPERM_WRITE:
            segHeader += "READWRITE"
        elif attr & SEGPERM_READ and not attr & SEGPERM_WRITE:
            segHeader += "READONLY"
        else:
            print "Warning: seg at 0x%X named %s does not have a read permission, please check!" % (ea, SegName(ea))
        segHeader += ("              ; Segment at %0"+ str(self.xlen * 2) +"X %s") % (ea, SegName(ea))
        self.out(segHeader)

    def calcOffsetTargetAndBase(self, ea, value):
        refi = opinfo_t()
        get_opinfo(ea, 0, GetFlags(ea), refi)

        reftarget = calc_reference_target(ea, refi.ri, value)
        return reftarget,refi.ri.base

    def getFirstXref(self, ea):
        for i in XrefsTo(ea):
            return i
    ########################################################
    ########################################################
    #似乎并不需要重新定位pc，因为不考虑relocation的情况下，pc是个常量
    #或许应该在translator里面处理这个的
    #但是这可能会导致hexrays无法正常工作QAQ
    #
    #决定重新定位pc，否则很可能会影响arm反汇编
    #否决上述决定
    #经试验后发现IDA可以处理这种情况，
    #重新决定为不重新定位pc
    ########################################################
    def makeOffsetExpression(self,ea,target,base):
        expression = ""
        expression += Name(target)
        if base != 0 and base == self.getFirstXref(ea):
            expression += " - "
            """if hasName(base):
                expression += Name(base)
            else:
                expression += ("loc_%0"+ str(self.xlen * 2) +"X") % (base)"""
            expression += "0x%X" % (base)
        return expression

    def doDataTranslation(self,ea):
        oriea = ea
        curline = ""
        curflag = GetFlags(ea)
        if not self.isCurInData:
            self.out("    DATA")
        if hasName(curflag):
            curline += Name(ea)
        if not isLoaded(ea):
            curline += "    DCB 0"
            ea += 1
        elif isData(curflag):
            if isOff0(curflag):
                if isByte(curflag):
                    curline += "    DCB "
                    target, base = self.calcOffsetTargetAndBase(ea, Byte(ea))
                    curline += self.makeOffsetExpression(ea, target, base)
                    ea += 1
                    print "Warning: Offset typed byte appeared"
                elif isWord(curflag):
                    curline += "    DCW "
                    target, base = self.calcOffsetTargetAndBase(ea, Word(ea))
                    curline += self.makeOffsetExpression(ea, target, base)
                    curline += Name(target)
                    ea += 2
                elif isDwrd(curflag):
                    curline += "    DCD "
                    target, base = self.calcOffsetTargetAndBase(ea, Dword(ea))
                    curline += self.makeOffsetExpression(ea, target, base)
                    curline += Name(target)
                    ea += 4
                elif isQwrd(curflag):
                    curline += "    DCQ "
                    target, base = self.calcOffsetTargetAndBase(ea, Qword(ea))
                    curline += self.makeOffsetExpression(ea, target, base)
                    curline += Name(target)
                    ea += 8
                else:
                    print ("Warning: not supported data type at %0"+str(self.xlen * 2)+"X") % (ea)
                    curline += "  DCB 0x%X\n" % (Byte(ea))
                    ea += 1
            else:
                if isByte(curflag):
                    curline += "  DCB 0x%X\n" % (Byte(ea))
                    ea += 1
                elif isWord(curflag):
                    curline += "  DCW 0x%X\n" % (Word(ea))
                    ea += 2
                elif isDwrd(curflag):
                    curline += "  DCD 0x%X\n" % (Dword(ea))
                    ea += 4
                elif isQwrd(curflag):
                    curline += "  DCQ 0x%X\n" % (Qword(ea))
                    ea += 8
                elif isOwrd(curflag):
                    for i in range(ea, ea + 16):
                        curline += "  DCB 0x%X\n" % (Byte(i))
                    ea += 16
                elif isYwrd(curflag):
                    for i in range(ea, ea + 32):
                        curline += "  DCB 0x%X\n" % (Byte(i))
                    ea += 32
                else:
                    curline += "  DCB 0x%X\n" % (Byte(ea))
                    ea += 1
        else:
            curline += "  DCB 0x%X\n" % (Byte(ea))
            ea += 1
        self.out(curline)
        return ea - oriea

    def cleanMnem(self, mnem):
        mnem.replace(".","_")
        mnem.replace(" ","_")
        return mnem

    def custom_action1(self):
        self.out("LTORG")

    def doCodeSegTranslation(self,ea):
        self.isCurInData = False
        lastLiteralPool = 0
        oriea = ea
        while ea < SegEnd(oriea):
            curline = ""
            if isCode(GetFlags(ea)):
                length = decode_insn(ea)
                if length <= 0:
                    length = self.doDataTranslation(ea)
                    lastLiteralPool += length
                    ea += length
                    continue
                mnem = GetMnem(ea)
                if hasName(GetFlags(ea)):
                    curline += Name(ea)
                    curline += ":"
                    self.out(curline)
                else:
                    #curline += ("loc_%0+"str(self.xlen * 2)"+X") % (ea)
                    #curline += ":"
                    #self.out(curline)
                    pass


                ########here!! dispatch the translator!!!
                mnem = self.cleanMnem(mnem)
                try:
                    getattr(self, 'translator_%s' % mnem)(ea,cmd)
                except AttributeError as e:
                    print ("%0"+str(self.xlen * 2)+"X: Warning: translator of %s instruction is not implemented! ") % (ea,mnem)
                    traceback.print_exc()
                except Exception as e:
                    self.out("NOP")
                    self.out("NOP")
                    self.out("NOP")
                    self.out("NOP")
                    print ("%0"+str(self.xlen * 2)+"X: %s") % (ea,repr(e))
                lastLiteralPool += 12
                ea += length
                continue
            else:
                length = self.doDataTranslation(ea)
                lastLiteralPool += length
                ea += length
            if lastLiteralPool >= 0x100000:
                self.custom_action1()

    def doOtherSegTranslation(self,ea):
        self.isCurInData = True
        oriea = ea
        while ea < SegEnd(oriea):
            ea += self.doDataTranslation(ea)
    def doExternSegTranslation(self,ea):
        oriea = ea
        while ea < SegEnd(oriea):
            curline = "     EXTERN "
            curline += Name(ea)
            curline += " WEAK"
            self.out(curline)
            ea += self.xlen
    def makeGlobalSegment(self):
        segHeader = "   AREA     "
        segHeader += ".global"
        segHeader += ", "
        segHeader += "DATA, "
        segHeader += "NOINIT, "
        segHeader += "READWRITE"
        segHeader += ("              ; Global segment")
        self.out(segHeader)
        for idx,name in enumerate(self.reg_names_target):
            curline = ""
            if name == self.temp_register:
                curline += "ori_register_%s" % (self.reg_names_origin[idx])
                curline += "SPACE %d" % (self.xlen)
            elif name == self.temp_register_gp:
                curline += "globalpointer_%s" % (self.reg_names_origin[idx])
                curline += "SPACE %d" % (self.xlen)
            self.out(curline)
        self.out("  END")

    reg_names_origin = [
        "zero", "ra", "sp", "gp", "tp",
        "t0", "t1", "t2", "s0",
        "s1", "a0", "a1", "a2", "a3",
        "a4", "a5", "a6", "a7", "s2", "s3", "s4", "s5",
        "s6", "s7", "s8", "s9", "s10",
        "s11", "t3", "t4", "t5", "t6",
    ]

    reg_names_target = [
        "", "LR", "SP", "R10", "R10",
        "R12", "R12", "R12", "R8",
        "R9", "R0", "R1", "R2", "R3",
        "R4", "R5", "R6", "R7", "R12","R12","R12","R12",
        "R12", "R12", "R12", "R12", "R12",
        "R12", "R12", "R12", "R12", "R12"
    ]
    temp_register = "R12"
    temp_register_addr = "R11"
    temp_register_gp = "R10"
    def premap_registers(self, ori_reg):
        if self.reg_names_target[ori_reg] == "":
            raise NoCorrespondingRegError()
        elif self.reg_names_target[ori_reg] == self.temp_register:
            self.out("LDR %s, =ori_register_%s" % (self.temp_register_addr, self.reg_names_origin[ori_reg]))
            self.out("LDR %s, [%s]" % (self.temp_register, self.temp_register_addr))
        elif self.reg_names_target[ori_reg] == self.temp_register_gp:
            self.out("LDR %s, =global_pointer_%s" % (self.temp_register_gp, self.reg_names_origin[ori_reg]))
            self.out("LDR %s, [%s]" % (self.temp_register_gp, self.temp_register_gp))
        return self.reg_names_target[ori_reg]

    def postmap_registers(self, ori_reg):
        if self.reg_names_target[ori_reg] == "":
            raise NoCorrespondingRegError()
        elif self.reg_names_target[ori_reg] == self.temp_register:
            self.out("LDR %s, =ori_register_%s" % (self.temp_register_addr, self.reg_names_origin[ori_reg]))
            self.out("STR %s, [%s]" % (self.temp_register, self.temp_register_addr))

    def translator_lui(self,ea,cmd):
        rd = self.premap_registers(cmd[0].reg)
        self.out("LDR %s,=0x%X" % (rd,cmd[1].value << 12 & 0xfffff))
    def translator_auipc(self,ea,cmd):
        rd = self.premap_registers(cmd[0].reg)
        self.out("LDR %s, =0x%X" % (rd, ea + cmd[1].value))
        self.postmap_registers(cmd[0].reg)
        pass
    def translator_jal(self,ea,cmd):
        if cmd[0].reg == 0:
            self.out("B %s" % (Name(cmd[1].addr)))
        elif cmd[0].reg == 1:
            self.out("BL %s" % (Name(cmd[1].addr)))
        else:
            rd = self.premap_registers(cmd[0].reg)
            self.out("LDR %s, =%s" % (rd,Name(cmd[1].addr)))
            self.postmap_registers(cmd[0].reg)

    def translator_jalr(self,ea,cmd):
        jump_ins = ""
        if cmd[0].reg == 0:
            jump_ins = "B"
        elif cmd[0].reg == 1:
            jump_ins = "BL"
        else:
            raise UnsupportedCornerCase("Warning: JALR translator does not support %s as link register" % (self.reg_names_origin[cmd[0].reg]))
        target_addr = 0
        try:
            target_addr = int(Comment(ea), 16)
        except:
            pass
        if target_addr != 0:
            self.out("%s %s" % (jump_ins,Name(target_addr)))
        elif cmd[0].reg == 0 and cmd[1].reg == 1 and cmd[1].addr == 0:
            self.out("BX LR")
        elif cmd[1].reg == 0:
            self.out("%s %s" % (jump_ins,Name(cmd[1].addr)))
        else:
            rd = self.premap_registers(cmd[1].reg)
            if cmd[1].addr == 0:
                self.out("%s %s" % (jump_ins,rd))
            else:
                print "Warning: JALR translator has to change the register %s in order to implement the corresponding instruction" % (self.reg_names_origin[cmd[1].reg])
                self.out("ADD %s, %s, %d" % (rd ,rd, cmd[1].addr))
                self.out("%s %s" % (jump_ins,rd))
        return

    def translator_beq(self,ea,cmd):
        if cmd[0].reg == 0:
            rs1 = self.premap_registers(cmd[1].reg)
            rs2 = "0"
        elif cmd[1].reg == 0:
            rs1 = self.premap_registers(cmd[0].reg)
            rs2 = "0"
        else:
            rs1 = self.premap_registers(cmd[0].reg)
            rs2 = self.premap_registers(cmd[1].reg)
        self.out("CMP %s, %s" % (rs1,rs2))
        self.out("BEQ %s" % (Name(cmd[2].addr)))
    def translator_bne(self,ea,cmd):
        if cmd[0].reg == 0:
            rs1 = self.premap_registers(cmd[1].reg)
            rs2 = "0"
        elif cmd[1].reg == 0:
            rs1 = self.premap_registers(cmd[0].reg)
            rs2 = "0"
        else:
            rs1 = self.premap_registers(cmd[0].reg)
            rs2 = self.premap_registers(cmd[1].reg)

        self.out("CMP %s, %s" % (rs1,rs2))
        self.out("BNE %s" % (Name(cmd[2].addr)))
    def translator_blt(self,ea,cmd):
        if cmd[0].reg == 0:
            rs1 = self.premap_registers(cmd[1].reg)
            rs2 = "0"
        elif cmd[1].reg == 0:
            rs1 = self.premap_registers(cmd[0].reg)
            rs2 = "0"
        else:
            rs1 = self.premap_registers(cmd[0].reg)
            rs2 = self.premap_registers(cmd[1].reg)

        self.out("CMP %s, %s" % (rs1,rs2))
        self.out("BLT %s" % (Name(cmd[2].addr)))
    def translator_bltu(self,ea,cmd):
        if cmd[0].reg == 0:
            rs1 = self.premap_registers(cmd[1].reg)
            rs2 = "0"
        elif cmd[1].reg == 0:
            rs1 = self.premap_registers(cmd[0].reg)
            rs2 = "0"
        else:
            rs1 = self.premap_registers(cmd[0].reg)
            rs2 = self.premap_registers(cmd[1].reg)

        self.out("CMP %s, %s" % (rs1,rs2))
        self.out("BLO %s" % (Name(cmd[2].addr)))
    def translator_bge(self,ea,cmd):
        if cmd[0].reg == 0:
            rs1 = self.premap_registers(cmd[1].reg)
            rs2 = "0"
        elif cmd[1].reg == 0:
            rs1 = self.premap_registers(cmd[0].reg)
            rs2 = "0"
        else:
            rs1 = self.premap_registers(cmd[0].reg)
            rs2 = self.premap_registers(cmd[1].reg)

        self.out("CMP %s, %s" % (rs1,rs2))
        self.out("BGE %s" % (Name(cmd[2].addr)))
    def translator_bgeu(self,ea,cmd):
        if cmd[0].reg == 0:
            rs1 = self.premap_registers(cmd[1].reg)
            rs2 = "0"
        elif cmd[1].reg == 0:
            rs1 = self.premap_registers(cmd[0].reg)
            rs2 = "0"
        else:
            rs1 = self.premap_registers(cmd[0].reg)
            rs2 = self.premap_registers(cmd[1].reg)

        self.out("CMP %s, %s" % (rs1,rs2))
        self.out("BHS %s" % (Name(cmd[2].addr)))
    def translator_lb(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        self.out("LDRSB %s, [%s, 0x%X]" % (rd,rs1,cmd[1].addr))
        self.postmap_registers(cmd[0].reg)
    def translator_lh(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        self.out("LDRSH %s, [%s, 0x%X]" % (rd,rs1,cmd[1].addr))
        self.postmap_registers(cmd[0].reg)
    def translator_lw(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        self.out("LDR %s, [%s, 0x%X]" % (rd,rs1,cmd[1].addr))
        self.postmap_registers(cmd[0].reg)
    def translator_lbu(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        self.out("LDRB %s, [%s, 0x%X]" % (rd,rs1,cmd[1].addr))
        self.postmap_registers(cmd[0].reg)
    def translator_lhu(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        self.out("LDRH %s, [%s, 0x%X]" % (rd,rs1,cmd[1].addr))
        self.postmap_registers(cmd[0].reg)
    def translator_sb(self, ea, cmd):
        if cmd[0].reg == 0:
            self.out("MOV %s, 0" % (self.temp_register_addr))
            rd = self.temp_register_addr
            rs1 = self.premap_registers(cmd[1].reg)
        elif cmd[1].reg == 0:
            self.out("MOV %s, 0" % (self.temp_register_addr))
            rd = self.premap_registers(cmd[0].reg)
            rs1 = self.temp_register_addr
        else:
            rd = self.premap_registers(cmd[0].reg)
            rs1 = self.premap_registers(cmd[1].reg)
    def translator_sh(self, ea, cmd):
        if cmd[0].reg == 0:
            self.out("MOV %s, 0" % (self.temp_register_addr))
            rd = self.temp_register_addr
            rs1 = self.premap_registers(cmd[1].reg)
        elif cmd[1].reg == 0:
            self.out("MOV %s, 0" % (self.temp_register_addr))
            rd = self.premap_registers(cmd[0].reg)
            rs1 = self.temp_register_addr
        else:
            rd = self.premap_registers(cmd[0].reg)
            rs1 = self.premap_registers(cmd[1].reg)
        self.out("STRH %s, [%s, 0x%X]" % (rd,rs1,cmd[1].addr))
    def translator_sw(self, ea, cmd):
        if cmd[0].reg == 0:
            self.out("MOV %s, 0" % (self.temp_register_addr))
            rd = self.temp_register_addr
            rs1 = self.premap_registers(cmd[1].reg)
        elif cmd[1].reg == 0:
            self.out("MOV %s, 0" % (self.temp_register_addr))
            rd = self.premap_registers(cmd[0].reg)
            rs1 = self.temp_register_addr
        else:
            rd = self.premap_registers(cmd[0].reg)
            rs1 = self.premap_registers(cmd[1].reg)
        self.out("STR %s, [%s, 0x%X]" % (rd,rs1,cmd[1].addr))
    def translator_addi(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        if cmd[1].reg == 0:
            self.out("MOV %s, 0x%X" % (rd,cmd[2].value))
        else:
            rs1 = self.premap_registers(cmd[1].reg)
            if cmd[2].value > 0:
                self.out("ADD %s, %s, 0x%X" % (rd, rs1, cmd[2].value))
            else:
                self.out("SUB %s, %s, 0x%X" % (rd, rs1, -cmd[2].value))
        self.postmap_registers(cmd[0].reg)
    def translator_slti(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        self.out("MOV %s, 0" % (rd))
        self.out("CMP %s, 0x%X" % (rs1, cmd[2].value))
        self.out("MOVLT %s, 1" % (rd))
        self.postmap_registers(cmd[0].reg)
    def translator_sltiu(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        self.out("MOV %s, 0" % (rd))
        self.out("CMP %s, 0x%X" % (rs1, cmd[2].value))
        self.out("MOVLO %s, 1" % (rd))
        self.postmap_registers(cmd[0].reg)
    def translator_xori(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        self.out("EOR %s, %s, 0x%X" % (rd, rs1, cmd[2].value))
        self.postmap_registers(cmd[0].reg)
    def translator_ori(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        self.out("OR %s, %s, 0x%X" % (rd, rs1, cmd[2].value))
        self.postmap_registers(cmd[0].reg)
    def translator_andi(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        self.out("AND %s, %s, 0x%X" % (rd, rs1, cmd[2].value))
        self.postmap_registers(cmd[0].reg)
    def translator_slli(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        self.out("LSL %s, %s, 0x%X" % (rd, rs1, cmd[2].value))
        self.postmap_registers(cmd[0].reg)
    def translator_srli(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        self.out("LOR %s, %s, 0x%X" % (rd, rs1, cmd[2].value))
    def translator_srai(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        self.out("ASR %s, %s, 0x%X" % (rd, rs1, cmd[2].value))
        self.postmap_registers(cmd[0].reg)
    def translator_add(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        if cmd[1].reg == 0 and cmd[2].reg == 0:
            return
        if cmd[1].reg == 0:
            rs2 = self.premap_registers(cmd[2].reg)
            self.out("MOV %s, %s" % (rd, rs2))
        elif cmd[2].reg == 0:
            rs1 = self.premap_registers(cmd[1].reg)
            self.out("MOV %s, %s" % (rd, rs1))
        else:
            rs1 = self.premap_registers(cmd[1].reg)
            rs2 = self.premap_registers(cmd[2].reg)
            self.out("ADD %s, %s, %s" % (rd, rs1, rs2))
        self.postmap_registers(cmd[0].reg)

    def translator_sub(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        if cmd[1].reg == 0 and cmd[2].reg == 0:
            return
        if cmd[1].reg == 0:
            rs2 = self.premap_registers(cmd[2].reg)
            self.out("RSB %s, %s, 0" % (rd, rs2))
        elif cmd[2].reg == 0:
            rs1 = self.premap_registers(cmd[1].reg)
            self.out("MOV %s, %s" % (rd, rs1))
        else:
            rs1 = self.premap_registers(cmd[1].reg)
            rs2 = self.premap_registers(cmd[2].reg)
            self.out("SUB %s, %s, %s" % (rd, rs1, rs2))
        self.postmap_registers(cmd[0].reg)
    def translator_sll(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        rs2 = self.premap_registers(cmd[2].reg)
        self.out("LSL %s, %s, %s" % (rd, rs1, rs2))
        self.postmap_registers(cmd[0].reg)
    def translator_slt(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        rs2 = self.premap_registers(cmd[2].reg)
        self.out("MOV %s, 0" % (rd))
        self.out("CMP %s, %s" % (rs1, rs2))
        self.out("MOVLT %s, 1" % (rd))
        self.postmap_registers(cmd[0].reg)
    def translator_sltu(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs2 = self.premap_registers(cmd[2].reg)
        if cmd[1].reg == 0:
            rs1 = rs2
        else:
            rs1 = self.premap_registers(cmd[1].reg)
        self.out("MOV %s, 0" % (rd))
        self.out("CMP %s, %s" % (rs1, rs2))
        self.out("MOVLO %s, 1" % (rd))
        self.postmap_registers(cmd[0].reg)
    def translator_xor(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        rs2 = self.premap_registers(cmd[2].reg)
        self.out("EOR %s, %s, %s" % (rd, rs1, rs2))
        self.postmap_registers(cmd[0].reg)
    def translator_srl(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        rs2 = self.premap_registers(cmd[2].reg)
        self.out("LSR %s, %s, %s" % (rd, rs1, rs2))
        self.postmap_registers(cmd[0].reg)
    def translator_sra(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        rs2 = self.premap_registers(cmd[2].reg)
        self.out("ASR %s, %s, %s" % (rd, rs1, rs2))
        self.postmap_registers(cmd[0].reg)
    def translator_or(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        rs2 = self.premap_registers(cmd[2].reg)
        self.out("OR %s, %s, %s" % (rd, rs1, rs2))
        self.postmap_registers(cmd[0].reg)
    def translator_and(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        rs2 = self.premap_registers(cmd[2].reg)
        self.out("AND %s, %s, %s" % (rd, rs1, rs2))
        self.postmap_registers(cmd[0].reg)
    def translator_mul(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        rs2 = self.premap_registers(cmd[2].reg)
        self.out("MUL %s, %s, %s" % (rd, rs1, rs2))
        self.postmap_registers(cmd[0].reg)
    def translator_div(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        rs2 = self.premap_registers(cmd[2].reg)
        self.out("SDIV %s, %s, %s" % (rd, rs1, rs2))
        self.postmap_registers(cmd[0].reg)
    def translator_divu(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        rs2 = self.premap_registers(cmd[2].reg)
        self.out("UDIV %s, %s, %s" % (rd, rs1, rs2))
        self.postmap_registers(cmd[0].reg)
    def translator_rem(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        rs2 = self.premap_registers(cmd[2].reg)
        self.out("SDIV %s, %s, %s" % (rd, rs1, rs2))
        self.out("MUL %s, %s, %s" % (rd, rd, rs2))
        self.out("SUB %s, %s, %s" % (rd, rs1, rd))
        self.postmap_registers(cmd[0].reg)
    def translator_remu(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        rs2 = self.premap_registers(cmd[2].reg)
        self.out("UDIV %s, %s, %s" % (rd, rs1, rs2))
        self.out("MUL %s, %s, %s" % (rd, rd, rs2))
        self.out("SUB %s, %s, %s" % (rd, rs1, rd))
        self.postmap_registers(cmd[0].reg)
def main():
    translator = openrisc_translator_arm("outasm.s")
    translator.printAsmHeader()
    for segea in Segments():
        attr = GetSegmentAttr(segea,SEGATTR_PERM)
        translator.printSegHeader(segea,attr)
        if SegName(segea) == ".plt":
            continue
        elif SegName(segea) == "extern":
            translator.doExternSegTranslation(segea)
        elif attr & SEGPERM_EXEC:
            translator.doCodeSegTranslation(segea)
        else:
            translator.doOtherSegTranslation(segea)
        translator.printAsmFooter()
    translator.makeGlobalSegment()
main()