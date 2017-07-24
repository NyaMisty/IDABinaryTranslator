# coding=utf-8

import pydevd
pydevd.settrace('localhost', port=15306, stdoutToServer=True, stderrToServer=True, suspend=False)

from idaapi import *
from idc import *
from idautils import *
import traceback

class NoCorrespondingRegError(Exception):
    pass

class UnsupportedCornerCase(Exception):
    pass

def SIGNEXT(x, b):
    m = 1 << (b - 1)
    x = x & ((1 << b) - 1)
    return (x ^ m) - m

class openrisc_translator_arm:
    f = None
    isCurInData = False
    xlen = 4
    curIndent = "   "
    lastLiteralPool = 0
    def __init__(self,name):
        self.f = open(name,"w")
    #辅助函数 可以自动处理indent 也可以在特殊情况指定indent
    def out(self, buf, indent=None):
        if not self.f is None:
            if indent is None:
                self.f.write(self.curIndent + buf + "\n")
            else:
                self.f.write(indent + buf + "\n")
    #生成label名称
    def getRealName(self,ea):
        name = Name(ea)
        if name != "":
            pass
        elif name == "" and isLoaded(ea):
            name = ("loc_%0" + str(self.xlen * 2) + "X") % (ea)
        else:
            name = ""
        return name
    #与processor协同 使用processor的分析结果
    def translateComment(self,ea):
        #ref = Comment(ea)
        target = BADADDR
        nn = netnode("$ simplified_addr", 0, False)
        if nn != BADNODE:
            target = nn.altval(ea)
        if target != BADADDR and target != 0:
            return target
        nn = netnode("$ simplified_const", 0, False)
        if nn != BADNODE:
            target = nn.altval(ea)
        if target == 0:
            return BADADDR
        if not isLoaded(target):
            return BADADDR
        return target
    #如果生成的汇编文件有header的话加在这里
    def printAsmHeader(self):
        pass

    # 如果生成的汇编文件有结尾的话加在这里
    def printAsmFooter(self):
        self.out("  END")
        pass

    # 每一个区段自己的header
    def printSegHeader(self,ea,attr):
        segHeader = "AREA    |"
        segHeader += SegName(ea)
        segHeader += "|"
        if attr & SEGPERM_EXEC:
            segHeader += ", CODE"
        else:
            segHeader += ", DATA"
        if not isLoaded(ea):
            segHeader += ", NOINIT"
        if attr & SEGPERM_READ and attr & SEGPERM_WRITE:
            segHeader += ", READWRITE"
        elif attr & SEGPERM_READ and not attr & SEGPERM_WRITE:
            segHeader += ", READONLY"
        else:
            print "Warning: seg at 0x%X named %s does not have a read permission, please check!" % (ea, SegName(ea))
        segHeader += ("              ; Segment at %0"+ str(self.xlen * 2) +"X %s") % (ea, SegName(ea))
        self.out(segHeader)
    #获取data中的offset
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
    #重新决定为不重定位pc
    ########################################################
    def makeOffsetExpression(self,ea,target,base):
        expression = ""
        expression += self.getRealName(target)
        if base != 0 and base == self.getFirstXref(ea):
            expression += " - "
            """if hasName(base):
                expression += self.getRealName(base)
            else:
                expression += ("loc_%0"+ str(self.xlen * 2) +"X") % (base)"""
            expression += "0x%X" % (base)
        return expression
    #上面的三个函数是想要处理重定位的，不过发现hexrays可以自动处理这些情况
    #所以如果还是需要处理的话就改上面的几个

    #翻译数据
    def doDataTranslation(self,ea):
        oriea = ea
        curline = ""
        curflag = GetFlags(ea)
        if not self.isCurInData:
            #self.out("DATA")
            self.isCurInData = True
        self.out(self.getRealName(ea),"")
        if not isLoaded(ea):
            curline += "DCB 0"
            ea += 1
        elif isData(curflag):
            if isOff0(curflag):
                if isByte(curflag):
                    curline += "DCB "
                    target, base = self.calcOffsetTargetAndBase(ea, Byte(ea))
                    curline += self.makeOffsetExpression(ea, target, base)
                    ea += 1
                    print "Warning: Offset typed byte appeared"
                elif isWord(curflag):
                    curline += "DCW "
                    target, base = self.calcOffsetTargetAndBase(ea, Word(ea))
                    curline += self.makeOffsetExpression(ea, target, base)
                    #curline += self.getRealName(target)
                    ea += 2
                elif isDwrd(curflag):
                    curline += "DCD "
                    target, base = self.calcOffsetTargetAndBase(ea, Dword(ea))
                    curline += self.makeOffsetExpression(ea, target, base)
                    #curline += self.getRealName(target)
                    ea += 4
                elif isQwrd(curflag):
                    curline += "DCQ "
                    target, base = self.calcOffsetTargetAndBase(ea, Qword(ea))
                    curline += self.makeOffsetExpression(ea, target, base)
                    #curline += self.getRealName(target)
                    ea += 8
                else:
                    print ("Warning: not supported data type at %0"+str(self.xlen * 2)+"X") % (ea)
                    curline += "DCB 0x%X\n" % (Byte(ea))
                    ea += 1
            else:
                if isByte(curflag):
                    curline += "DCB 0x%X\n" % (Byte(ea))
                    ea += 1
                elif isWord(curflag):
                    curline += "DCW 0x%X\n" % (Word(ea))
                    ea += 2
                elif isDwrd(curflag):
                    curline += "DCD 0x%X\n" % (Dword(ea))
                    ea += 4
                elif isQwrd(curflag):
                    curline += "DCQ 0x%X\n" % (Qword(ea))
                    ea += 8
                elif isOwrd(curflag):
                    for i in range(ea, ea + 16):
                        curline += "DCB 0x%X\n" % (Byte(i))
                    ea += 16
                elif isYwrd(curflag):
                    for i in range(ea, ea + 32):
                        curline += "DCB 0x%X\n" % (Byte(i))
                    ea += 32
                else:
                    curline += "DCB 0x%X\n" % (Byte(ea))
                    ea += 1
        else:
            curline += "DCB 0x%X\n" % (Byte(ea))
            ea += 1
        self.out(curline)
        return ea - oriea
    #避免助记符中带有特殊字符
    def cleanMnem(self, mnem):
        mnem.replace(".","_")
        mnem.replace(" ","_")
        return mnem

    #ARM中规定必须要4k之内有一个literal pool
    def custom_action1(self, ea):
        self.out("B %s" % (self.getRealName(ea)))
        self.out("LTORG")
        self.lastLiteralPool = 0

    # 翻译指令
    def doCodeSegTranslation(self,ea):
        self.isCurInData = False
        oriea = ea
        while ea < SegEnd(oriea):
            curline = ""
            if isCode(GetFlags(ea)):
                if self.isCurInData:
                    self.isCurInData = False
                    self.out("ALIGN")
                length = decode_insn(ea)
                if length <= 0:
                    length = self.doDataTranslation(ea)
                    self.lastLiteralPool += length
                    ea += length
                    continue

                if self.lastLiteralPool >= 0x900:
                    self.custom_action1(ea)

                mnem = GetMnem(ea)
                curline += self.getRealName(ea)
                #curline += "    NOP"
                self.out(curline, "")
                ########here!! dispatch the translator!!!
                mnem = self.cleanMnem(mnem)
                try:
                    getattr(self, 'translator_%s' % mnem)(ea,cmd)
                except AttributeError as e:
                    print ("%0"+str(self.xlen * 2)+"X: Warning: translator of %s instruction is not implemented! ") % (ea,mnem)
                    traceback.print_exc()
                #如果出现异常 那么就用4个nop填充一下，以便修复和鉴别
                except Exception as e:
                    self.out("NOP")
                    self.out("NOP")
                    self.out("NOP")
                    self.out("NOP")
                    print ("%0"+str(self.xlen * 2)+"X: %s") % (ea,repr(e))
                self.lastLiteralPool += 12
                ea += length
                continue
            else:
                length = self.doDataTranslation(ea)
                self.lastLiteralPool += length
                ea += length

    #处理数据区段
    def doOtherSegTranslation(self,ea):
        self.isCurInData = True
        oriea = ea
        while ea < SegEnd(oriea):
            ea += self.doDataTranslation(ea)
    #处理导出区段
    def doExternSegTranslation(self,ea):
        oriea = ea
        while ea < SegEnd(oriea):
            curline = "     EXTERN "
            curline += self.getRealName(ea)
            curline += "[WEAK]"
            self.out(curline)
            ea += self.xlen
    #增加用于存储多出来的寄存器的区段
    def makeGlobalSegment(self):
        segHeader = "AREA |"
        segHeader += ".global"
        segHeader += "|, "
        segHeader += "DATA, "
        segHeader += "NOINIT, "
        segHeader += "READWRITE"
        segHeader += ("              ; Global segment")
        self.out(segHeader)
        for idx,name in enumerate(self.reg_names_target):
            curline = ""
            if name == self.temp_register:
                curline += "ori_register_%s    " % (self.reg_names_origin[idx])
                curline += "SPACE %d" % (self.xlen)
            elif name == self.temp_register_gp:
                self.out("SPACE %d" % (1000))
                curline += "global_pointer_%s    " % (self.reg_names_origin[idx])
                curline += "SPACE %d" % (1000)
            self.out(curline,"")

    #下面是寄存器的映射关系
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
        "R8", "R8", "R8", "R8",
        "R8", "R0", "R1", "R2", "R3",
        "R4", "R5", "R6", "R7", "R8","R8","R8","R8",
        "R8", "R8", "R8", "R8", "R8",
        "R8", "R8", "R8", "R8", "R8"
    ]
    #temp_register_addr存储多出来的寄存器的地址
    #temp_register_gp用于处理gp寄存器的使用
    #temp_register 存储多出来寄存器的值
    #temp_register_offset 用于处理内存访问时offset大于可支持范围的情况
    temp_register = "R8"
    temp_register_addr = "R11"
    temp_register_gp = "R10"
    temp_register_offset = "R9"
    def premap_registers(self, ori_reg):
        if self.reg_names_target[ori_reg] == "":
            raise NoCorrespondingRegError()
        elif self.reg_names_target[ori_reg] == self.temp_register:
            self.out("LDR %s, =ori_register_%s" % (self.temp_register_addr, self.reg_names_origin[ori_reg]))
            self.out("LDR %s, [%s]" % (self.temp_register, self.temp_register_addr))
        elif self.reg_names_target[ori_reg] == self.temp_register_gp:
            self.out("LDR %s, =global_pointer_%s" % (self.temp_register_gp, self.reg_names_origin[ori_reg]))
        return self.reg_names_target[ori_reg]

    def postmap_registers(self, ori_reg):
        if self.reg_names_target[ori_reg] == "":
            raise NoCorrespondingRegError()
        elif self.reg_names_target[ori_reg] == self.temp_register:
            self.out("LDR %s, =ori_register_%s" % (self.temp_register_addr, self.reg_names_origin[ori_reg]))
            self.out("STR %s, [%s]" % (self.temp_register, self.temp_register_addr))

    #下面就是translator了，注意特殊情况的处理哦
    #可能大量算数运算是无需进行更改的
    def translator_lui(self,ea,cmd):
        rd = self.premap_registers(cmd[0].reg)
        self.out("LDR %s,=0x%X" % (rd,cmd[1].value << 12 & 0xfffff))
    def translator_auipc(self,ea,cmd):
        rd = self.premap_registers(cmd[0].reg)
        self.out("LDR %s, =0x%X" % (rd, ea + cmd[1].value))
        self.postmap_registers(cmd[0].reg)
        pass
    #
    # 跳转指令
    # 注意特殊情况
    #
    #
    #
    def translator_jal(self,ea,cmd):
        if cmd[0].reg == 0:
            self.out("B %s" % (self.getRealName(cmd[1].addr)))
        elif cmd[0].reg == 1:
            self.out("BL %s" % (self.getRealName(cmd[1].addr)))
        else:
            rd = self.premap_registers(cmd[0].reg)
            self.out("LDR %s, =%s" % (rd,self.getRealName(cmd[1].addr)))
            self.postmap_registers(cmd[0].reg)

    def translator_jalr(self,ea,cmd):
        jump_ins = ""
        if cmd[0].reg == 0:
            jump_ins = "BX"
        elif cmd[0].reg == 1:
            jump_ins = "BLX"
        else:
            raise UnsupportedCornerCase("Warning: JALR translator does not support %s as link register" % (self.reg_names_origin[cmd[0].reg]))
        target_addr = 0
        try:
            target_addr = int(Comment(ea), 16)
        except:
            pass
        if target_addr != 0:
            self.out("%s %s" % (jump_ins,self.getRealName(target_addr)))
        elif cmd[0].reg == 0 and cmd[1].reg == 1 and cmd[1].addr == 0:
            self.out("BX LR")
        elif cmd[1].reg == 0:
            self.out("%s %s" % (jump_ins,self.getRealName(cmd[1].addr)))
        else:
            rd = self.premap_registers(cmd[1].reg)
            if cmd[1].addr == 0:
                self.out("%s %s" % (jump_ins,rd))
            else:
                print "Warning: JALR translator has to change the register %s in order to implement the corresponding instruction" % (self.reg_names_origin[cmd[1].reg])
                self.out("ADD %s, %s, #%d" % (rd ,rd, cmd[1].addr))
                self.out("%s %s" % (jump_ins,rd))
        return

    def translator_beq(self,ea,cmd):
        if cmd[0].reg == 0:
            rs1 = self.premap_registers(cmd[1].reg)
            rs2 = "#0"
        elif cmd[1].reg == 0:
            rs1 = self.premap_registers(cmd[0].reg)
            rs2 = "#0"
        else:
            rs1 = self.premap_registers(cmd[0].reg)
            rs2 = self.premap_registers(cmd[1].reg)
        self.out("CMP %s, %s" % (rs1,rs2))
        self.out("BEQ %s" % (self.getRealName(cmd[2].addr)))
    def translator_bne(self,ea,cmd):
        if cmd[0].reg == 0:
            rs1 = self.premap_registers(cmd[1].reg)
            rs2 = "#0"
        elif cmd[1].reg == 0:
            rs1 = self.premap_registers(cmd[0].reg)
            rs2 = "#0"
        else:
            rs1 = self.premap_registers(cmd[0].reg)
            rs2 = self.premap_registers(cmd[1].reg)

        self.out("CMP %s, %s" % (rs1,rs2))
        self.out("BNE %s" % (self.getRealName(cmd[2].addr)))
    def translator_blt(self,ea,cmd):
        if cmd[0].reg == 0:
            rs1 = self.premap_registers(cmd[1].reg)
            rs2 = "#0"
        elif cmd[1].reg == 0:
            rs1 = self.premap_registers(cmd[0].reg)
            rs2 = "#0"
        else:
            rs1 = self.premap_registers(cmd[0].reg)
            rs2 = self.premap_registers(cmd[1].reg)

        self.out("CMP %s, %s" % (rs1,rs2))
        self.out("BLT %s" % (self.getRealName(cmd[2].addr)))
    def translator_bltu(self,ea,cmd):
        if cmd[0].reg == 0:
            rs1 = self.premap_registers(cmd[1].reg)
            rs2 = "#0"
        elif cmd[1].reg == 0:
            rs1 = self.premap_registers(cmd[0].reg)
            rs2 = "#0"
        else:
            rs1 = self.premap_registers(cmd[0].reg)
            rs2 = self.premap_registers(cmd[1].reg)

        self.out("CMP %s, %s" % (rs1,rs2))
        self.out("BLO %s" % (self.getRealName(cmd[2].addr)))
    def translator_bge(self,ea,cmd):
        if cmd[0].reg == 0:
            rs1 = self.premap_registers(cmd[1].reg)
            rs2 = "#0"
        elif cmd[1].reg == 0:
            rs1 = self.premap_registers(cmd[0].reg)
            rs2 = "#0"
        else:
            rs1 = self.premap_registers(cmd[0].reg)
            rs2 = self.premap_registers(cmd[1].reg)

        self.out("CMP %s, %s" % (rs1,rs2))
        self.out("BGE %s" % (self.getRealName(cmd[2].addr)))
    def translator_bgeu(self,ea,cmd):
        if cmd[0].reg == 0:
            rs1 = self.premap_registers(cmd[1].reg)
            rs2 = "#0"
        elif cmd[1].reg == 0:
            rs1 = self.premap_registers(cmd[0].reg)
            rs2 = "#0"
        else:
            rs1 = self.premap_registers(cmd[0].reg)
            rs2 = self.premap_registers(cmd[1].reg)

        self.out("CMP %s, %s" % (rs1,rs2))
        self.out("BHS %s" % (self.getRealName(cmd[2].addr)))
    #
    # 内存存取指令
    # 注意特殊情况
    #
    #
    #
    def translator_lb(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        target = self.translateComment(ea)
        if target != BADADDR:
            self.out("LDR %s, =%s" % (self.temp_register_offset, self.getRealName(target)))
            self.out("LDRSB %s, [%s]" % (rd, self.temp_register_offset))
        elif SIGNEXT(cmd[1].addr,32) <= -255 or SIGNEXT(cmd[1].addr,32) >= 4095:
            self.out("LDR %s, =0x%X" % (self.temp_register_offset, cmd[1].addr))
            self.out("LDRSB %s, [%s, %s]" % (rd, rs1, self.temp_register_offset))
        else:
            self.out("LDRSB %s, [%s, #0x%X]" % (rd,rs1,cmd[1].addr))
        self.postmap_registers(cmd[0].reg)
    def translator_lh(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        target = self.translateComment(ea)
        if target != BADADDR:
            self.out("LDR %s, =%s" % (self.temp_register_offset, self.getRealName(target)))
            self.out("LDRSH %s, [%s]" % (rd, self.temp_register_offset))
        elif SIGNEXT(cmd[1].addr,32) <= -255 or SIGNEXT(cmd[1].addr,32) >= 4095:
            self.out("LDR %s, =0x%X" % (self.temp_register_offset, cmd[1].addr))
            self.out("LDRSH %s, [%s, %s]" % (rd, rs1, self.temp_register_offset))
        else:
            self.out("LDRSH %s, [%s, #0x%X]" % (rd,rs1,cmd[1].addr))
        self.postmap_registers(cmd[0].reg)
    def translator_lw(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        target = self.translateComment(ea)
        if target != BADADDR:
            self.out("LDR %s, =%s" % (self.temp_register_offset, self.getRealName(target)))
            self.out("LDR %s, [%s]" % (rd, self.temp_register_offset))
        elif SIGNEXT(cmd[1].addr,32) <= -255 or SIGNEXT(cmd[1].addr,32) >= 4095:
            self.out("LDR %s, =0x%X" % (self.temp_register_offset, cmd[1].addr))
            self.out("LDR %s, [%s, %s]" % (rd, rs1, self.temp_register_offset))
        else:
            self.out("LDR %s, [%s, #0x%X]" % (rd,rs1,cmd[1].addr))
        self.postmap_registers(cmd[0].reg)
    def translator_lbu(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        target = self.translateComment(ea)
        if target != BADADDR:
            self.out("LDR %s, =%s" % (self.temp_register_offset, self.getRealName(target)))
            self.out("LDRB %s, [%s]" % (rd, self.temp_register_offset))
        elif SIGNEXT(cmd[1].addr,32) <= -255 or SIGNEXT(cmd[1].addr,32) >= 4095:
            self.out("LDR %s, =0x%X" % (self.temp_register_offset, cmd[1].addr))
            self.out("LDRB %s, [%s, %s]" % (rd, rs1, self.temp_register_offset))
        else:
            self.out("LDRB %s, [%s, #0x%X]" % (rd,rs1,cmd[1].addr))
        self.postmap_registers(cmd[0].reg)
    def translator_lhu(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        target = self.translateComment(ea)
        if target != BADADDR:
            self.out("LDR %s, =%s" % (self.temp_register_offset, self.getRealName(target)))
            self.out("LDRSB %s, [%s]" % (rd, self.temp_register_offset))
        elif SIGNEXT(cmd[1].addr,32) <= -255 or SIGNEXT(cmd[1].addr,32) >= 4095:
            self.out("LDR %s, =0x%X" % (self.temp_register_offset, cmd[1].addr))
            self.out("LDRH %s, [%s, %s]" % (rd, rs1, self.temp_register_offset))
        else:
            self.out("LDRH %s, [%s, #0x%X]" % (rd,rs1,cmd[1].addr))
        self.postmap_registers(cmd[0].reg)
    def translator_sb(self, ea, cmd):
        if cmd[0].reg == 0:
            self.out("MOV %s, #0" % (self.temp_register_addr))
            rd = self.temp_register_addr
            rs1 = self.premap_registers(cmd[1].reg)
        elif cmd[1].reg == 0:
            self.out("MOV %s, #0" % (self.temp_register_addr))
            rd = self.premap_registers(cmd[0].reg)
            rs1 = self.temp_register_addr
        else:
            rd = self.premap_registers(cmd[0].reg)
            rs1 = self.premap_registers(cmd[1].reg)
        if SIGNEXT(cmd[1].addr,32) <= -255 or SIGNEXT(cmd[1].addr,32) >= 4095:
            self.out("LDR %s, =0x%X" % (self.temp_register_offset, cmd[1].addr))
            self.out("STRB %s, [%s, %s]" % (rd, rs1, self.temp_register_offset))
        else:
            self.out("STRB %s, [%s, #0x%X]" % (rd, rs1, cmd[1].addr))
    def translator_sh(self, ea, cmd):
        if cmd[0].reg == 0:
            self.out("MOV %s, #0" % (self.temp_register_addr))
            rd = self.temp_register_addr
            rs1 = self.premap_registers(cmd[1].reg)
        elif cmd[1].reg == 0:
            self.out("MOV %s, #0" % (self.temp_register_addr))
            rd = self.premap_registers(cmd[0].reg)
            rs1 = self.temp_register_addr
        else:
            rd = self.premap_registers(cmd[0].reg)
            rs1 = self.premap_registers(cmd[1].reg)
        if SIGNEXT(cmd[1].addr,32) <= -255 or SIGNEXT(cmd[1].addr,32) >= 4095:
            self.out("LDR %s, =0x%X" % (self.temp_register_offset, cmd[1].addr))
            self.out("STRH %s, [%s, %s]" % (rd, rs1, self.temp_register_offset))
        else:
            self.out("STRH %s, [%s, #0x%X]" % (rd,rs1,cmd[1].addr))
    def translator_sw(self, ea, cmd):
        if cmd[0].reg == 0:
            self.out("MOV %s, #0" % (self.temp_register_addr))
            rd = self.temp_register_addr
            rs1 = self.premap_registers(cmd[1].reg)
        elif cmd[1].reg == 0:
            self.out("MOV %s, #0" % (self.temp_register_addr))
            rd = self.premap_registers(cmd[0].reg)
            rs1 = self.temp_register_addr
        else:
            rd = self.premap_registers(cmd[0].reg)
            rs1 = self.premap_registers(cmd[1].reg)
        if SIGNEXT(cmd[1].addr,32) <= -255 or SIGNEXT(cmd[1].addr,32) >= 4095:
            self.out("LDR %s, =0x%X" % (self.temp_register_offset, cmd[1].addr))
            self.out("STR %s, [%s, %s]" % (rd, rs1, self.temp_register_offset))
        else:
            self.out("STR %s, [%s, #0x%X]" % (rd,rs1,cmd[1].addr))
    #
    # 加减乘除
    # 注意特殊情况的处理
    # 注意有无符号
    #
    #
    def translator_addi(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        if cmd[1].reg == 0:
            self.out("LDR %s, =0x%X" % (rd,cmd[2].value))
        elif self.translateComment(ea) != BADADDR:
            self.out("LDR %s, =%s" % (rd,self.getRealName(self.translateComment(ea))))
            pass
        else:
            rs1 = self.premap_registers(cmd[1].reg)
            if SIGNEXT(cmd[2].value, 32) > 0:
                self.out("LDR %s, =0x%X" % (self.temp_register_offset, cmd[2].value))
                self.out("ADD %s, %s, %s" % (rd, rs1, self.temp_register_offset))
            else:
                self.out("LDR %s, =0x%X" % (self.temp_register_offset, -SIGNEXT(cmd[2].value, 32)))
                self.out("SUB %s, %s, %s" % (rd, rs1, self.temp_register_offset))
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
            self.out("RSB %s, %s, #0" % (rd, rs2))
        elif cmd[2].reg == 0:
            rs1 = self.premap_registers(cmd[1].reg)
            self.out("MOV %s, %s" % (rd, rs1))
        else:
            rs1 = self.premap_registers(cmd[1].reg)
            rs2 = self.premap_registers(cmd[2].reg)
            self.out("SUB %s, %s, %s" % (rd, rs1, rs2))
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
        self.postmap_registers(cmd[0].reg)
    #
    # 与或非
    # 逻辑运算
    # 注意逻辑右移和算数右移
    #
    def translator_xori(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        if cmd[2].value > 255:
            self.out("LDR %s, =0x%X" % (self.temp_register_offset,cmd[2].value))
            self.out("EOR %s, %s, %s" % (rd, rs1, self.temp_register_offset))
        else:
            self.out("EOR %s, %s, #0x%X" % (rd, rs1, cmd[2].value))
        self.postmap_registers(cmd[0].reg)
    def translator_ori(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        if cmd[2].value > 255:
            self.out("LDR %s, =0x%X" % (self.temp_register_offset,cmd[2].value))
            self.out("ORR %s, %s, %s" % (rd, rs1, self.temp_register_offset))
        else:
            self.out("ORR %s, %s, #0x%X" % (rd, rs1, cmd[2].value))
        self.postmap_registers(cmd[0].reg)
    def translator_andi(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        if cmd[2].value > 255:
            self.out("LDR %s, =0x%X" % (self.temp_register_offset,cmd[2].value))
            self.out("AND %s, %s, %s" % (rd, rs1, self.temp_register_offset))
        else:
            self.out("AND %s, %s, #0x%X" % (rd, rs1, cmd[2].value))
        self.postmap_registers(cmd[0].reg)
    def translator_slli(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        self.out("LSL %s, %s, #0x%X" % (rd, rs1, cmd[2].value))
        self.postmap_registers(cmd[0].reg)
    #逻辑右移
    def translator_srli(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        self.out("LSR %s, %s, #0x%X" % (rd, rs1, cmd[2].value))
    #算数右移
    def translator_srai(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        self.out("ASR %s, %s, #0x%X" % (rd, rs1, cmd[2].value))
        self.postmap_registers(cmd[0].reg)
    def translator_sll(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        rs2 = self.premap_registers(cmd[2].reg)
        self.out("LSL %s, %s, %s" % (rd, rs1, rs2))
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
        self.out("ORR %s, %s, %s" % (rd, rs1, rs2))
        self.postmap_registers(cmd[0].reg)
    def translator_and(self, ea, cmd):
        rd = self.premap_registers(cmd[0].reg)
        rs1 = self.premap_registers(cmd[1].reg)
        rs2 = self.premap_registers(cmd[2].reg)
        self.out("AND %s, %s, %s" % (rd, rs1, rs2))
        self.postmap_registers(cmd[0].reg)


def main():
    translator = openrisc_translator_arm("outasm.s")
    translator.printAsmHeader()
    for segea in Segments():
        if SegName(segea) == ".plt":
            continue
        attr = GetSegmentAttr(segea,SEGATTR_PERM)
        translator.curIndent = "  "
        translator.printSegHeader(segea,attr)
        translator.curIndent = "    "
        if SegName(segea) == "extern":
            translator.doExternSegTranslation(segea)
        elif attr & SEGPERM_EXEC:
            translator.doCodeSegTranslation(segea)
        else:
            translator.doOtherSegTranslation(segea)
        translator.curIndent = "  "
    translator.curIndent = "  "
    translator.makeGlobalSegment()
    translator.printAsmFooter()
main()