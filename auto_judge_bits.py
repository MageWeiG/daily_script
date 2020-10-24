import sys

def read_target_file(file_path):
    with open(file_path,'rb') as f:
        file_h = f.read(80)
        f.close()
    return file_h

def judge_system(file_he):
    if (file_he[0] == 127 and file_he[1:4] == b'ELF'):
        return "Linux"
    elif (file_he[0:2] == b'MZ'):
        return "Windows"
    else:
        return "Error"

def judge_linux_bits(file_he):
    if (file_he[4] == 1):
        return 32
    elif (file_he[4] == 2):
        return 64
    else:
        return 0

def Convert(ss):
    if len(ss) == 3:
        if ss[-1] == "a" or ss[-1] == "A":
            ss = 10
        elif ss[-1] == "b" or ss[-1] == "B":
            ss = 11
        elif ss[-1] == "c" or ss[-1] == "C":
            ss = 12
        elif ss[-1] == "d" or ss[-1] == "D":
            ss = 13
        elif ss[-1] == "e" or ss[-1] == "E":
            ss = 14
        elif ss[-1] == "f" or ss[-1] == "F":
            ss = 15
        else:
            ss = int(ss[-1])
    elif len(ss) == 4:
        if ss[-1] == "a" or ss[-1] == "A":
            ss1 = 10
        elif ss[-1] == "b" or ss[-1] == "B":
            ss1 = 11
        elif ss[-1] == "c" or ss[-1] == "C":
            ss1 = 12
        elif ss[-1] == "d" or ss[-1] == "D":
            ss1 = 13
        elif ss[-1] == "e" or ss[-1] == "E":
            ss1 = 14
        elif ss[-1] == "f" or ss[-1] == "F":
            ss1 = 15
        else:
            ss1 = int(ss[-1])


        if ss[-2:-1] == "a" or ss[-2:-1] == "A":
            ss2 = 10*16
        elif ss[-2:-1] == "b" or ss[-2:-1] == "B":
            ss2 = 11*16
        elif ss[-2:-1] == "c" or ss[-2:-1] == "C":
            ss2 = 12*16
        elif ss[-2:-1] == "d" or ss[-2:-1] == "D":
            ss2 = 13*16
        elif ss[-2:-1] == "e" or ss[-2:-1] == "E":
            ss2 = 14*16
        elif ss[-2:-1] == "f" or ss[-2:-1] == "F":
            ss2 = 15*16
        else:
            ss2 = int(ss[-2:-1])*16


        ss = ss1 + ss2            
    
    return ss


def Convert_H(ss):
    if len(ss) == 3:
        if ss[-1] == "a" or ss[-1] == "A":
            ss = 10*16*16
        elif ss[-1] == "b" or ss[-1] == "B":
            ss = 11*16*16
        elif ss[-1] == "c" or ss[-1] == "C":
            ss = 12*16*16
        elif ss[-1] == "d" or ss[-1] == "D":
            ss = 13*16*16
        elif ss[-1] == "e" or ss[-1] == "E":
            ss = 14*16*16
        elif ss[-1] == "f" or ss[-1] == "F":
            ss = 15*16*16
        else:
            ss = int(ss[-1])*16*16
    elif len(ss) == 4:
        if ss[-1] == "a" or ss[-1] == "A":
            ss1 = 10*16*16
        elif ss[-1] == "b" or ss[-1] == "B":
            ss1 = 11*16*16
        elif ss[-1] == "c" or ss[-1] == "C":
            ss1 = 12*16*16
        elif ss[-1] == "d" or ss[-1] == "D":
            ss1 = 13*16*16
        elif ss[-1] == "e" or ss[-1] == "E":
            ss1 = 14*16*16
        elif ss[-1] == "f" or ss[-1] == "F":
            ss1 = 15*16*16
        else:
            ss1 = int(ss[-1])*16*16


        if ss[-2:-1] == "a" or ss[-2:-1] == "A":
            ss2 = 10*16*16*16
        elif ss[-2:-1] == "b" or ss[-2:-1] == "B":
            ss2 = 11*16*16*16
        elif ss[-2:-1] == "c" or ss[-2:-1] == "C":
            ss2 = 12*16*16*16
        elif ss[-2:-1] == "d" or ss[-2:-1] == "D":
            ss2 = 13*16*16*16
        elif ss[-2:-1] == "e" or ss[-2:-1] == "E":
            ss2 = 14*16*16*16
        elif ss[-2:-1] == "f" or ss[-2:-1] == "F":
            ss2 = 15*16*16*16
        else:
            ss2 = int(ss[-2:-1])*16*16*16


        ss = ss1 + ss2            
    
    return ss

def CheckDll(target_file_path, one, two):
    res_num = int(one) + int(two) + 6


    f = open(target_file_path, "rb").read(res_num)


    for c in f[res_num-2:res_num-1]:
        #print("f[res_num-2:res_num-1]",hex(ord(c)))
        s_1 = hex(c)
        
    for c in f[res_num-1:res_num]:
        #print("f[res_num-1:res_num]",hex(ord(c)))
        s_2 = hex(c)


    if s_1 == "0x4c" and s_2 == "0x1":
        print("This program run in 32bit system!")
        return 32
    elif s_1 == "0x64" and s_2 == "0x86":
        print("This program run in 64bit system!")
        return 64
    else:
        print("Error!"+s_1+s_2)
        return 0

def judge_windows_bit(file_he,target_file_path):
    s1 = file_he[60:61]
    s2 = file_he[61:62]
    
    return CheckDll(target_file_path,Convert(hex(ord(s1))),Convert_H(hex(ord(s2))))


def main():
    target_file = sys.argv[1]

    #read file head from target file
    file_head = read_target_file(target_file)

    #judge this PE file run on windows or linux
    file_system = ''
    file_system = judge_system(file_head)

    #judge this PE file run on 32 bits system or 64 bits
    file_bit = 0
    if file_system == "Linux":
        file_bit = judge_linux_bits(file_head)
    elif file_system == "Windows":
        file_bit = judge_windows_bit(file_head,target_file)
    else:
        file_bit = 0

    return (file_system,file_bit)


def write_result_to_file(result):
    pass

if __name__ == "__main__":
    print(main())
    
