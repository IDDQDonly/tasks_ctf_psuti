

with open("flag.txt", encoding='ASCII') as f:
    g = f.read()

    cp=[]
    for i in g:
        cp.append(ord(i))
    print(cp)
    ch=[]

    for i in cp:
        ch.append(1337*i % 123 ^ ord("a") ^ ord("b") ^ ord("c"))
    cp=[]
    for i in ch:
        cp.append(chr(i))
    print(cp)
    y = " ".join(str(x) for x in cp)
    with open("chipher.txt",'w') as c:
        c.write(y)
    print(y)
