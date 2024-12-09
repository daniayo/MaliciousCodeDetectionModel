import csv
import os
import pefile
import yara
import math
import hashlib

class PEFeatures:

    IMAGE_DOS_HEADER = [
        "e_cblp", "e_cp", "e_cparhdr", "e_maxalloc", "e_sp", "e_lfanew"
    ]

    FILE_HEADER = ["NumberOfSections", "CreationYear"] + ["FH_char" + str(i) for i in range(15)]

    OPTIONAL_HEADER1 = [
        "MajorLinkerVersion", "MinorLinkerVersion", "SizeOfCode", "SizeOfInitializedData", "SizeOfUninitializedData",
        "AddressOfEntryPoint", "BaseOfCode", "BaseOfData", "ImageBase", "SectionAlignment", "FileAlignment",
        "MajorOperatingSystemVersion", "MinorOperatingSystemVersion", "MajorImageVersion", "MinorImageVersion",
        "MajorSubsystemVersion", "MinorSubsystemVersion", "SizeOfImage", "SizeOfHeaders", "CheckSum", "Subsystem"
    ]

    OPTIONAL_HEADER_DLL_char = ["OH_DLLchar" + str(i) for i in range(11)]
    OPTIONAL_HEADER2 = [
        "SizeOfStackReserve", "SizeOfStackCommit", "SizeOfHeapReserve", "SizeOfHeapCommit", "LoaderFlags"
    ]

    OPTIONAL_HEADER = OPTIONAL_HEADER1 + OPTIONAL_HEADER_DLL_char + OPTIONAL_HEADER2
    DERIVED_HEADER = [
        "sus_sections", "non_sus_sections", "packer", "packer_type", "E_text", "E_data", "filesize", "E_file", "fileinfo"
    ]

    def __init__(self, source, output, label):
        self.source = source
        self.output = output
        self.type = label
        self.rules = yara.compile(filepath='./peid.yara')

    def file_creation_year(self, seconds):
        return int(1970 + ((int(seconds) / 86400) / 365) in range(1980, 2022))

    def FILE_HEADER_Char_boolean_set(self, pe):
        tmp = [
            pe.FILE_HEADER.IMAGE_FILE_RELOCS_STRIPPED,
            pe.FILE_HEADER.IMAGE_FILE_EXECUTABLE_IMAGE,
            pe.FILE_HEADER.IMAGE_FILE_LINE_NUMS_STRIPPED,
            pe.FILE_HEADER.IMAGE_FILE_LOCAL_SYMS_STRIPPED,
            pe.FILE_HEADER.IMAGE_FILE_AGGRESIVE_WS_TRIM,
            pe.FILE_HEADER.IMAGE_FILE_LARGE_ADDRESS_AWARE,
            pe.FILE_HEADER.IMAGE_FILE_BYTES_REVERSED_LO,
            pe.FILE_HEADER.IMAGE_FILE_32BIT_MACHINE,
            pe.FILE_HEADER.IMAGE_FILE_DEBUG_STRIPPED,
            pe.FILE_HEADER.IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP,
            pe.FILE_HEADER.IMAGE_FILE_NET_RUN_FROM_SWAP,
            pe.FILE_HEADER.IMAGE_FILE_SYSTEM,
            pe.FILE_HEADER.IMAGE_FILE_DLL,
            pe.FILE_HEADER.IMAGE_FILE_UP_SYSTEM_ONLY,
            pe.FILE_HEADER.IMAGE_FILE_BYTES_REVERSED_HI
        ]
        return [int(s) for s in tmp]

    def OPTIONAL_HEADER_DLLChar(self, pe):
        tmp = [
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY,
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_ISOLATION,
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_SEH,
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_BIND,
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_WDM_DRIVER,
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE,
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA,
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_APPCONTAINER,
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_GUARD_CF
        ]
        return [int(s) for s in tmp]

    def Optional_header_ImageBase(self, ImageBase):
        result = 0
        if ImageBase % (64 * 1024) == 0 and ImageBase in [268435456, 65536, 4194304]:
            result = 1
        return result

    def Optional_header_SectionAlignment(self, SectionAlignment, FileAlignment):
        return int(SectionAlignment >= FileAlignment)

    def Optional_header_FileAlignment(self, SectionAlignment, FileAlignment):
        result = 0
        if SectionAlignment >= 512:
            if FileAlignment % 2 == 0 and FileAlignment in range(512, 65537):
                result = 1
        else:
            if FileAlignment == SectionAlignment:
                result = 1
        return result

    def Optional_header_SizeOfImage(self, SizeOfImage, SectionAlignment):
        return int(SizeOfImage % SectionAlignment == 0)

    def Optional_header_SizeOfHeaders(self, SizeOfHeaders, FileAlignment):
        return int(SizeOfHeaders % FileAlignment == 0)

    def extract_dos_header(self, pe):
        IMAGE_DOS_HEADER_data = [0 for i in range(6)]
        try:
            IMAGE_DOS_HEADER_data = [
                pe.DOS_HEADER.e_cblp,
                pe.DOS_HEADER.e_cp,
                pe.DOS_HEADER.e_cparhdr,
                pe.DOS_HEADER.e_maxalloc,
                pe.DOS_HEADER.e_sp,
                pe.DOS_HEADER.e_lfanew
            ]
        except Exception as e:
            print(e)
        return IMAGE_DOS_HEADER_data

    def extract_file_header(self, pe):
        FILE_HEADER_data = [0 for i in range(3)]
        FILE_HEADER_char = []
        try:
            FILE_HEADER_data = [
                pe.FILE_HEADER.NumberOfSections,
                self.file_creation_year(pe.FILE_HEADER.TimeDateStamp)
            ]
            FILE_HEADER_char = self.FILE_HEADER_Char_boolean_set(pe)
        except Exception as e:
            print(e)
        return FILE_HEADER_data + FILE_HEADER_char

    def extract_optional_header(self, pe):
        OPTIONAL_HEADER_data = [0 for i in range(21)]
        DLL_char = []
        OPTIONAL_HEADER_data2 = [0 for i in range(6)]
        try:
            OPTIONAL_HEADER_data = [
                pe.OPTIONAL_HEADER.MajorLinkerVersion,
                pe.OPTIONAL_HEADER.MinorLinkerVersion,
                pe.OPTIONAL_HEADER.SizeOfCode,
                pe.OPTIONAL_HEADER.SizeOfInitializedData,
                pe.OPTIONAL_HEADER.SizeOfUninitializedData,
                pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                pe.OPTIONAL_HEADER.BaseOfCode,
                pe.OPTIONAL_HEADER.BaseOfData,
                self.Optional_header_ImageBase(pe.OPTIONAL_HEADER.ImageBase),
                self.Optional_header_SectionAlignment(pe.OPTIONAL_HEADER.SectionAlignment, pe.OPTIONAL_HEADER.FileAlignment),
                self.Optional_header_FileAlignment(pe.OPTIONAL_HEADER.SectionAlignment, pe.OPTIONAL_HEADER.FileAlignment),
                pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
                pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
                pe.OPTIONAL_HEADER.MajorImageVersion,
                pe.OPTIONAL_HEADER.MinorImageVersion,
                pe.OPTIONAL_HEADER.MajorSubsystemVersion,
                pe.OPTIONAL_HEADER.MinorSubsystemVersion,
                self.Optional_header_SizeOfImage(pe.OPTIONAL_HEADER.SizeOfImage, pe.OPTIONAL_HEADER.SectionAlignment),
                self.Optional_header_SizeOfHeaders(pe.OPTIONAL_HEADER.SizeOfHeaders, pe.OPTIONAL_HEADER.FileAlignment),
                pe.OPTIONAL_HEADER.CheckSum,
                pe.OPTIONAL_HEADER.Subsystem
            ]
            DLL_char = self.OPTIONAL_HEADER_DLLChar(pe)

            OPTIONAL_HEADER_data2 = [
                pe.OPTIONAL_HEADER.SizeOfStackReserve,
                pe.OPTIONAL_HEADER.SizeOfStackCommit,
                pe.OPTIONAL_HEADER.SizeOfHeapReserve,
                pe.OPTIONAL_HEADER.SizeOfHeapCommit,
                int(pe.OPTIONAL_HEADER.LoaderFlags == 0)
            ]
        except Exception as e:
            print(e)
        return OPTIONAL_HEADER_data + DLL_char + OPTIONAL_HEADER_data2

    def get_count_suspicious_sections(self, pe):
    	benign_sections = {'.text', '.data', '.rdata', '.idata', '.edata', '.rsrc', '.bss', '.crt', '.tls'}
    	try:
        	tmp = [section.Name.decode('utf-8', errors = 'ignore').split('\x00')[0] for section in pe.sections]
    	except AttributeError:
        	print(f"Error processing section names in file: {filepath}")
        	tmp = []
    	non_sus_sections = len(set(tmp).intersection(benign_sections))
    	return [len(tmp) - non_sus_sections, non_sus_sections]


    def check_packer(self, filepath):
        result = []
        matches = self.rules.match(filepath)
        try:
            if not matches:
                result.append([0, "NoPacker"])
            else:
                result.append([1, matches['main'][0]['rule']])
        except:
            result.append([1, "UnknownPacker"])
        return result

    def get_text_data_entropy(self, pe):
    	entropy_sections = []
    	for section in pe.sections:
        	try:
            		s_name = section.Name.decode('utf-8', errors='ignore').split('\x00')[0]
        	except UnicodeDecodeError:
            		s_name = section.Name.decode('latin-1').split('\x00')[0]
        	entropy_sections.append(s_name)
    	return entropy_sections



    def get_file_bytes_size(self, filepath):
        with open(filepath, "rb") as f:
            byteArr = list(f.read())
        fileSize = len(byteArr)
        return byteArr, fileSize

    def cal_byteFrequency(self, byteArr, fileSize):
        freqList = []
        for b in range(256):
            ctr = 0
            for byte in byteArr:
                if byte == b:
                    ctr += 1
            freqList.append(float(ctr) / fileSize)
        return freqList

    def get_base_of_data(self, pe):
    	if hasattr(pe, 'OPTIONAL_HEADER') and hasattr(pe.OPTIONAL_HEADER, 'BaseOfData'):
        	return pe.OPTIONAL_HEADER.BaseOfData
    	else:
        	return None

    def get_file_entropy(self, filepath):
        byteArr, fileSize = self.get_file_bytes_size(filepath)
        freqList = self.cal_byteFrequency(byteArr, fileSize)
        ent = 0.0
        for freq in freqList:
            if freq > 0:
                ent += -freq * math.log(freq, 2)
        return [fileSize, ent]

    def get_fileinfo(self, pe):
        result = []
        try:
            FileVersion = pe.FileInfo[0].StringTable[0].entries['FileVersion']
            ProductVersion = pe.FileInfo[0].StringTable[0].entries['ProductVersion']
            ProductName = pe.FileInfo[0].StringTable[0].entries['ProductName']
            CompanyName = pe.FileInfo[0].StringTable[0].entries['CompanyName']
            FileVersionLS = pe.VS_FIXEDFILEINFO.FileVersionLS
            FileVersionMS = pe.VS_FIXEDFILEINFO.FileVersionMS
            ProductVersionLS = pe.VS_FIXEDFILEINFO.ProductVersionLS
            ProductVersionMS = pe.VS_FIXEDFILEINFO.ProductVersionMS
        except Exception as e:
            result = ["error"]
        else:
            FileVersion = (FileVersionMS >> 16, FileVersionMS & 0xFFFF, FileVersionLS >> 16, FileVersionLS & 0xFFFF)
            ProductVersion = (ProductVersionMS >> 16, ProductVersionMS & 0xFFFF, ProductVersionLS >> 16, ProductVersionLS & 0xFFFF)
            result = [FileVersion, ProductVersion, ProductName, CompanyName]
        return int(result[0] != 'error')

    def write_csv_header(self):
        filepath = self.output
        HASH = ['filename', 'MD5']
        header = HASH + self.IMAGE_DOS_HEADER + self.FILE_HEADER + self.OPTIONAL_HEADER + self.DERIVED_HEADER
        header.append("class")
        with open(filepath, "w", newline='') as csv_file:
            writer = csv.writer(csv_file, delimiter=',')
            writer.writerow(header)

    def extract_all(self, filepath):
        data = []
        try:
            pe = pefile.PE(filepath)
            print(f"[*] Processing - {filepath}")
        except Exception as e:
            print(f"{e} while opening {filepath}")
        else:
        #just for Raw Features
            data += self.extract_dos_header(pe)
            data += self.extract_file_header(pe)
            data += self.extract_optional_header(pe)
	#For Derived Features
            num_ss_nss = self.get_count_suspicious_sections(pe)
            data += num_ss_nss
            packer = self.check_packer(filepath)
            data += packer[0]
            entropy_sections = self.get_text_data_entropy(pe)
            data += entropy_sections
            fileinfo = self.get_fileinfo(pe)
            data.append(fileinfo)
            data.append(self.type)
        return data

    def write_csv_data(self, data):
        filepath = self.output
        with open(filepath, "a", newline='') as csv_file:
            writer = csv.writer(csv_file, delimiter=',')
            writer.writerow(data)

    def getMD5(self, filepath):
        with open(filepath, 'rb') as file:
            m = hashlib.md5()
            while chunk := file.read(8192):
                m.update(chunk)
        return m.hexdigest()

    def create_dataset(self):
        self.write_csv_header()		#create csv_header
        count = 0

        for file in os.listdir(self.source):
            filepath = os.path.join(self.source, file)
            data = self.extract_all(filepath) 	#extract all the features!!
            hash_ = self.getMD5(filepath)
            data.insert(0, hash_)
            data.insert(0, file)

            self.write_csv_data(data)		#report in csv_data
            count += 1
            print(f"Successfully Data extracted and written for {file}.")
            print(f"Processed {count} files")


def main():
    source_path = input("Enter the path of samples (ending with/) >> ")
    output_file = input("Give file name of output file. (.csv) >> ")
    label = input("Enter type of sample (malware(1) | normal(0)) >> ")

    features = PEFeatures(source_path, output_file, label)
    features.create_dataset()


if __name__ == '__main__':
    main()
