import os
import pefile
import operator
from itertools import chain
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

class NGRAM_features:
    def __init__(self):
        self.gram = dict()

    def gen_list_n_gram(self, num, asm_list):
        for i in range(0, len(asm_list), num):
            yield asm_list[i:i+num]

    def n_grams(self, num, asm_list, ex_mode):
        gram = self.gram if ex_mode == 1 else dict()

        gen_list = self.gen_list_n_gram(num, asm_list)

        for lis in gen_list:
            lis = " ".join(lis)
            gram[lis] = gram.get(lis, 0) + 1

        return gram

    def get_ngram_count(self, headers, grams, label):
        patterns = [grams.get(pat, 0) for pat in headers]
        patterns.append(label)
        return patterns

    def get_opcodes(self, mode, file):
        asm = []
        try:
            pe = pefile.PE(file)
        except pefile.PEFormatError:
            print(f"[ERROR] PE file format error: {file} is not a valid PE file or is empty.")
            return [] 

        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        end = pe.OPTIONAL_HEADER.SizeOfCode
        ep_ava = ep + pe.OPTIONAL_HEADER.ImageBase

        for section in pe.sections:
            addr = section.VirtualAddress
            size = section.Misc_VirtualSize
            
            if ep > addr and ep < (addr + size):
                ep = addr
                end = size

        data = pe.get_memory_mapped_image()[ep:ep + end]
        temp = data.hex()
        temp = [temp[i:i + 2] for i in range(0, len(temp), 2)]

        if mode:
            return temp

        # Capstone Disassembler
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.detail = False

        for insn in md.disasm(data, 0x401000):
            asm.append(insn.mnemonic)

        return asm

def extract_features(file_path, ngram_extractor, ngram_size=4):
    data = []
    try:
        byte_code = ngram_extractor.get_opcodes(0, file_path)
        if not byte_code:
            return None
        grams = ngram_extractor.n_grams(ngram_size, byte_code, 0)
        data = grams 
    except Exception as e:
        print(f"Error while processing {file_path}: {e}")
    return data

def create_feature_vector(grams, headers):
    return grams.get_ngram_count(headers, grams, 0) if grams else []

