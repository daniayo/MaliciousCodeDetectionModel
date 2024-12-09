import os
import pefile
import time
import array
import dis
import operator
import csv
import hashlib

from itertools import chain
from capstone import *
from capstone.x86 import *

class NGRAM_features:
    def __init__(self, output):
        
        self.output = output
        self.gram = dict()
        self.imports = ""

    def gen_list_n_gram(self, num, asm_list):
        for i in range(0, len(asm_list), num):
            yield asm_list[i:i+num]

    def n_grams(self, num, asm_list, ex_mode):
        if ex_mode == 1:
            gram = self.gram
        elif ex_mode == 0:
            gram = dict()

        gen_list = self.gen_list_n_gram(num, asm_list)

        for lis in gen_list:
            lis = " ".join(lis)
            try:
                gram[lis] += 1
            except:
                gram[lis] = 1    

        return gram

    def get_ngram_count(self, headers, grams, label):
        patterns = list()

        for pat in headers:
            try:
                patterns.append(grams[pat])
            except:
                patterns.append(0)

        patterns.append(label)
        return patterns

    def find_entry_point_section(self, pe, eop_rva):
        for section in pe.sections:
            if section.contains_rva(eop_rva):
                return section
        return None

    def get_opcodes(self, mode, file):
        asm = []
        try:
            pe = pefile.PE(file)
        except pefile.PEFormatError:
            print(f"[ERROR] PE file format error: {file} is not a valid PE file or is empty.")
            return [] 

        byte_all = []
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
        offset = 0
        
        temp = data.hex()
        temp = [temp[i:i + 2] for i in range(0, len(temp), 2)]

        if mode:
            return temp

        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.detail = False

        for insn in md.disasm(data, 0x401000):
            print(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")
            asm.append(insn.mnemonic)

        return asm

    def getMD5(self, filepath):
        with open(filepath, 'rb') as fh:
            m = hashlib.md5()
            while True:
                data = fh.read(8192)
                if not data:
                    break
                m.update(data)
            return m.hexdigest()

    def write_csv_header(self, headers):
        filepath = self.output
        HASH = ['filename', 'MD5']
        class_ = ['class']
        headers = HASH + headers + class_

        with open(filepath, "w", newline="") as csv_file:
            writer = csv.writer(csv_file, delimiter=',')
            writer.writerow(headers)

    def write_csv_data(self, data):
        filepath = self.output
        with open(filepath, "a", newline="") as csv_file:
            writer = csv.writer(csv_file, delimiter=',')
            writer.writerow(data)

def main():    

    num_of_features = 100

    mal_path = 'samples/malware_samples/'
    nor_path = 'samples/normal_samples/'
    output_file = "ngram.csv"

    print ('[*] Extracting ngram patterns from files')

    ef = NGRAM_features(output_file)
    i = 0

    # From here - Step1 : Extract own 4-gram pattern from malware/normal files
    for file in os.listdir(mal_path):  
        i += 1 
        print ("%d file processed (%s)," % (i, file))
        file = mal_path + file       
        byte_code = ef.get_opcodes(0, file) 
        if not byte_code: 
            continue
        grams = ef.n_grams(4, byte_code, 1)
        print ("%d patterns extracted" % (len(grams)))

    print ("- Malware Completed")
    
    for file in os.listdir(nor_path):  
        i += 1
        print ("%d file processed (%s)," % (i, file))
        file = nor_path + file       
        byte_code = ef.get_opcodes(0, file) 
        if not byte_code:
            continue
        grams = ef.n_grams(4, byte_code, 1)
        print ("%d patterns extracted" % (len(grams)))
    print ("- Normal Completed")
    
    # From here - Step2 : By extracting Top 100 patterns, Make those into Features
    print ("[*] Total length of 4-gram list :", len(grams))

    sorted_x = sorted(grams.items(), key=operator.itemgetter(1), reverse=True)
    print ("[*] Using %s grams as features" % (num_of_features))
    features = sorted_x[0:num_of_features]
    headers = list(chain.from_iterable(zip(*features)))[0:num_of_features]
    ef.write_csv_header(headers)

    print ("#" * 80)
    
    # From Here - Step3 : Selecting the patterns (which is Top 100) in each file, record the frequency in csv
    i = 0
    for file in os.listdir(mal_path):  
        i += 1
        print ("%d file processed (%s)," % (i, file))
        filepath = mal_path + file
        byte_code = ef.get_opcodes(0, filepath)
        if not byte_code:  
            continue
        grams = ef.n_grams(4, byte_code, 0)
        
        gram_count = ef.get_ngram_count(headers, grams, 1)  
        hash_ = ef.getMD5(filepath)
        all_data = [file, hash_]
        all_data.extend(gram_count)   
        ef.write_csv_data(all_data)   

    for file in os.listdir(nor_path):  
        i += 1
        print ("%d file processed (%s)," % (i, file))
        
        filepath = nor_path + file       
        byte_code = ef.get_opcodes(0, filepath) 
        if not byte_code:  
            continue
        grams = ef.n_grams(4, byte_code, 0) 
        gram_count = ef.get_ngram_count(headers, grams, 0) 

        hash_ = ef.getMD5(filepath)
        all_data = [file, hash_]
        all_data.extend(gram_count)   
        ef.write_csv_data(all_data)

if __name__ == '__main__':
    main()

