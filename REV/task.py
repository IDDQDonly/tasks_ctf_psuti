def check_pass(password):
    symbols = []
    password = [password[i] for i in [12,9,5,2,3,10,0,1,4,14,6,7,11,8,13,15]]
    print(password)
    for symbol in password:
        symbols.append(ord(symbol))

    if symbols[0] + 10 == 105 and symbols[1] + 1337 == 1419 and chr(symbols[2] + 30) == '}' and \
            chr(int(symbols[3] * symbols[4]/1785)) == '\x04' and chr(symbols[3] + symbols[4] - 70) == 'c' and \
            chr(symbols[5]) == '3' and int(symbols[6]/2) == 40 and int(symbols[7]/3) == 12 and \
            chr(symbols[6]-symbols[7]) == ',' and chr(symbols[7] ^ symbols[8]) == 'm' and chr(symbols[9]) == '3' and \
            chr(symbols[11]*symbols[12]/51 == "T") and chr(symbols[10]-symbols[9] + 1 == "!") and chr(symbols[12]-symbols[7]) == "0" and \
            chr(symbols[13]) == "C" and chr(symbols[13] + symbols [15] - 30) == "~" and chr(int((symbols[14]*1337 + symbols[15]-78)/1223)) == "R":

        print('Правильно!! быстрее вводи в форму')
    else:
        print('Попробуй ещё раз')


check_pass('P$UTI_S3CR3T_K3Y')



