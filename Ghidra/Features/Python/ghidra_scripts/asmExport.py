import os
import codecs
import re
import sys
import subprocess
from binascii import unhexlify

from __main__ import currentProgram
from ghidra.app.cmd.data import CreateDataCmd
from ghidra.program.database import ProgramAddressFactory
from ghidra.program.model.address import AddressSet
from ghidra.framework import ApplicationConfiguration
from ghidra.app.services import ProgramManager
from docking.widgets.filechooser import GhidraFile
from ghidra.program.model.lang import LanguageID
from ghidra.program.util import DefaultLanguageService
from ghidra.program.model.data import ByteDataType, WordDataType, DWordDataType, QWordDataType, LongDoubleDataType
from java.io import File

scriptFolder = os.path.abspath(os.path.dirname(__file__))
mainFolder = os.path.join(scriptFolder,"..","..","..","..")
procFolder = os.path.join(mainFolder,"Ghidra","Processors")
radare2Folder = os.path.join(mainFolder,"radare2","bin")
outFolder = os.path.join(mainFolder,"out")

config = ApplicationConfiguration()

program = currentProgram
monitor = config.getTaskMonitor()

api = ghidra.program.flatapi.FlatProgramAPI(program,monitor)

path = program.getExecutablePath().lstrip("/")
fileSize = int(os.path.getsize(path))
print("Size: " + str(fileSize) + " bytes")
name = os.path.splitext(os.path.basename(path))[0]
print("Input: " + path)

rabinPath = os.path.join(radare2Folder,"rabin2.exe")

proc = subprocess.Popen([ rabinPath, "-e", path ], stdout=subprocess.PIPE)

path = os.path.join(outFolder,os.path.basename(path))
file = File(path)
path = file.getAbsolutePath()

(entryPoint, err) = proc.communicate()
entryPoint = re.findall(r'0x[0-9a-fA-F]+', entryPoint)[0].replace("0x","LAB_")

print("Start: " + entryPoint)

lang = program.getLanguage()
compilerSpec = program.getCompilerSpec()
arch = re.findall(r'[^:]+:', str(program.getLanguageID()))[0][0:-1]
bits = int(re.findall(r':\d+:', str(program.getLanguageID()))[0][1:-1])
endian = "LE"
if str(program.getLanguageID()).replace(":BE:","") != str(program.getLanguageID()):
    endian = "BE"

print("Arch: " + arch + " " + endian + " (" + str(bits) + " bit)")

Addressor = ProgramAddressFactory(lang,compilerSpec)

programContext = ghidra.program.util.ProgramContextImpl(lang)

memoryStart = program.getMinAddress()
memory = program.getMemory()
memoryBlocks = api.getMemoryBlocks()
memoryView = memory.getAllInitializedAddressSet()

listingObj = program.getListing()

def Analyze():
    api.start()
    api.analyzeAll(program)
    api.end(True)

def MemFix():
    for block in memoryBlocks:
        api.start()
        block.setWrite(False)
        api.end(True)

def Disassemble():

    disassembled = "global main\n"
    disassembled += "\nsection .text\n"
    disassembled += "\nmain:\njmp " + entryPoint + "\n"
    
    api.start()
    for addr in iter(memoryView.getAddresses(True)):
        if addr.toString() == entryPoint:
            for block in memoryBlocks:
                if block.contains(addr):
                    api.disassemble(block.getStart())
                    break
            break
    api.end(True)

    refs = []
    instructionAddrs = []

    instructions = iter(listingObj.getInstructions(True))
    for i in instructions:
        cntx = i.getInstructionContext()
        addr = cntx.getAddress()
        print("Code: " + addr.toString())
        codeUnit = listingObj.getCodeUnitAt(addr)
        _refs = codeUnit.getReferencesFrom()    
        codeUnitStr = str(codeUnit)
        for r in _refs:
            a = r.getToAddress()
            isData = r.getReferenceType().isData()
            if isData:
                refs.append(r)

        codeUnitStr = codeUnitStr.lower()
        codeUnitStr = codeUnitStr.replace("lab_","LAB_")
        codeUnitStr = codeUnitStr.replace("cmpxchg.lock","lock cmpxchg")
        codeUnitStr = codeUnitStr.replace("[0x","[LAB_")
        codeUnitStr = codeUnitStr.replace(" ptr "," ")
        codeUnitStr = codeUnitStr.replace("xmmword "," ")

        check2 = re.findall(r'\.rep[n]?[ze]?', codeUnitStr)
        if len(check2) > 0:
            codeUnitStr = check2[0][1:] + " " + codeUnitStr.replace(check2[0],"")

        check3 = re.findall(r'stos[bwdq]|lods[bwdq]', codeUnitStr)
        if len(check3) > 0:
            if check3[0] == "lodsb":
                reg = codeUnitStr.replace("lodsb ","").replace("rep ","")
                size = "al"
                codeUnitStr = "mov " + size + ",[" + reg + "]\ninc " + reg
            elif check3[0] == "lodsw":
                reg = codeUnitStr.replace("lodsw ","").replace("rep ","")
                size = "ax"
                codeUnitStr = "mov " + size + ",[" + reg + "]\ninc " + reg
                codeUnitStr += "\ninc " + reg
            elif check3[0] == "lodsd":
                reg = codeUnitStr.replace("lodsd ","").replace("rep ","")
                size = "eax"
                codeUnitStr = "mov " + size + ",[" + reg + "]\ninc " + reg
                codeUnitStr += "\ninc " + reg
                codeUnitStr += "\ninc " + reg
                codeUnitStr += "\ninc " + reg
            elif check3[0] == "lodsq":
                reg = codeUnitStr.replace("lodsq ","").replace("rep ","")
                size = "rax"
                codeUnitStr = "mov " + size + ",[" + reg + "]\ninc " + reg
                codeUnitStr += "\ninc " + reg
                codeUnitStr += "\ninc " + reg
                codeUnitStr += "\ninc " + reg
                codeUnitStr += "\ninc " + reg
                codeUnitStr += "\ninc " + reg
                codeUnitStr += "\ninc " + reg
                codeUnitStr += "\ninc " + reg
            elif check3[0] == "stosb":
                reg = codeUnitStr.replace("stosb ","").replace("rep ","")
                size = "al"
                codeUnitStr = "mov [ss:" + reg + "]," + size + "\ninc " + reg
            elif check3[0] == "stosw":
                reg = codeUnitStr.replace("stosw ","").replace("rep ","")
                size = "ax"
                codeUnitStr = "mov [ss:" + reg + "]," + size + "\ninc " + reg
                codeUnitStr += "\ninc " + reg
            elif check3[0] == "stosd":
                reg = codeUnitStr.replace("stosd ","").replace("rep ","")
                size = "eax"
                codeUnitStr = "mov [ss:" + reg + "]," + size + "\ninc " + reg
                codeUnitStr += "\ninc " + reg
                codeUnitStr += "\ninc " + reg
                codeUnitStr += "\ninc " + reg
            elif check3[0] == "stosq":
                reg = codeUnitStr.replace("stosq ","").replace("rep ","")
                size = "rax"
                codeUnitStr = "mov [ss:" + reg + "]," + size + "\ninc " + reg
                codeUnitStr += "\ninc " + reg
                codeUnitStr += "\ninc " + reg
                codeUnitStr += "\ninc " + reg
                codeUnitStr += "\ninc " + reg
                codeUnitStr += "\ninc " + reg
                codeUnitStr += "\ninc " + reg
                codeUnitStr += "\ninc " + reg

        check4 = re.findall(r'scas[bwdq]|ins[bwdq]|movs[bwdq]', codeUnitStr)
        if len(check4) > 0:
            codeUnitStr = check4[0]

        check5 = re.findall( r' LAB_[0-9a-f]+' , codeUnitStr )
        if len(check5) > 0:
            codeUnitStr = codeUnitStr.replace(check5[0], " [" + check5[0][1:] + "]" )

        check1 = re.findall(r'\[LAB_[0-9a-f]{1,7}\]|\[LAB_[0-9a-f]{1,7} ',codeUnitStr)
        if len(check1) > 0:
            codeUnitStr = codeUnitStr.replace( "LAB_" , "0x" )

        codeUnitStr = codeUnitStr.replace("[[","[")
        codeUnitStr = codeUnitStr.replace("]]","]")

        check6 = re.findall( r'call 0x[0-9a-f]{8,}|j(mp|[n]?[zcsegl]{1,2}) 0x[0-9a-f]{8,}',codeUnitStr)
        if len(check6) > 0:
            codeUnitStr = codeUnitStr.replace( "0x" , "LAB_" )

        disassembled += "\n; " + codeUnit.getMinAddress().toString() + " -> " + codeUnit.getMaxAddress().toString()
        disassembled += "\nLAB_"+addr.toString() + ":\n" + codeUnitStr + "\n"
        instructionAddrs.append(addr.toString())

    disassembled2 = disassembled.split("\n")
    disassembled3 = []
    for line in disassembled2:
        check = re.findall(r'(call|j(mp|[n]?[zcsegl]{1,2})) ([dq]?word|byte) (\[LAB_[0-9a-f]+\])', line)
        if len(check) is 0 or re.findall(r'LAB_[0-9a-f]+', ' '.join([str(x) for x in check[0]]))[0].replace("LAB_","") in instructionAddrs:
            disassembled3.append(line)
        else:
            disassembled3.append("; "+line)

    disassembled = "\n".join(disassembled3)

    disassembled += "\nsection .data\n"

    lnks = []

    for ref in refs:
        addr = ref.getToAddress().toString()
        if addr not in lnks:
                lnks.append(addr)

    bsses = []
    for lnk in lnks:
        if lnk in instructionAddrs:
            continue
        print("Data: " + lnk)
        addr = Addressor.getAddress(lnk)
        label = "LAB_" + lnk
        if memoryView.contains(addr):
            dataIter = iter(api.getBytes(addr,fileSize))
            data = []
            for di in dataIter:
                if int(di) == 0:
                    data.append("00h")
                    continue
                if int(di) < 0:
                    di = di & (2**bits-1)
                di = hex(di).replace("0x","").replace("L","")
                di = di[len(di)-2:]
                data.append("0x"+di.zfill(2))
            data = ",".join(data)
            while data.endswith(',00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h'):
                data = data[:-1024]
            while data.endswith(',00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h'):
                data = data[:-128]
            while data.endswith(',00h,00h,00h,00h,00h,00h,00h,00h'):
                data = data[:-32]
            while data.endswith(',00h,00h,00h,00h'):
                data = data[:-16]
            while data.endswith(',00h'):
                data = data[:-4]
            disassembled += "\n" + label + ": db " + data + "\n"
        else:
            if lnk not in bsses:
                bsses.append(lnk)

    disassembled += "\nsection .bss\n"

    for lnk in bsses:
        if lnk in instructionAddrs:
            continue
        print("Bss: " + lnk)
        if len(re.findall(r'Stack', lnk)) == 0:
            name = "LAB_" + lnk
            disassembled += "\n" + name + ": resb 16\n"

    return disassembled

MemFix()
print("Analyzing...")
Analyze()
print("Disassembling...")
disassembled = Disassemble()
print("Disassembled")

lowOut = os.path.join(outFolder,name+".asm")
print("Output: " + os.path.normpath(lowOut))
low = codecs.open(lowOut, "w","utf-8")
low.write(disassembled)
low.close()
