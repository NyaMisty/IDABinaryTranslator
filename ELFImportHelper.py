#please make all plt entry into separate functions instead of function trunks

from idaapi import *
from idc import *

externStart = 0x00042FF4
ea = externStart
pltstubstart = 0x00011920
pltstubea = pltstubstart

while pltstubea < SegEnd(pltstubstart):
    MakeName(pltstubea, "")
    pltstubea = NextFchunk(pltstubea)

pltstubea = pltstubstart

while pltstubea < SegEnd(pltstubstart):
    MakeName(pltstubea, Name(ea))
    ea += 4
    pltstubea = NextFchunk(pltstubea)