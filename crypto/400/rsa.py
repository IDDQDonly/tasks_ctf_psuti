#!/usr/bin/env python3.7
'''
Demonstrate the RSA algorithm key generation, encryption and
decryption with a simple padding scheme.
It is useful for understanding how RSA works in an ecosystem of
padding and translation to encrypt and decrypt text information.
It was written because many of examples of RSA do a great job
of describing the algorithm but they do not show an end to end
solution.
Here are some known results that can be used for verification with
small numbers.
      p        q        e            d
   -------  -------  -------  ==> -------
         3       11        3            7
         3       11        7            3
        11       13        7          103
        11       13      103            7
        53       59        3         2011
        53       59     2011            3
Note the symmetry of e and d.
A more complex example from
http://doctrina.org/How-RSA-Works-With-Examples.html:
   p = 12131072439211271897323671531612440428472427633701410925634549312301964373042085619324197365322416866541017057361365214171711713797974299334871062829803541
   q = 12027524255478748885956220793734512128733387803682075433653899983955179850988797899869146900809131611153346817050832096022160146366346391812470987105415233
   e = 65537
   d = 89489425009274444368228545921773093919669586065884257445497854456487674839629818390934941973262879616797970608917283679875499331574161113854088813275488110588247193077582527278437906504015680623423550067240042466665654232383502922215493623289472138866445818789127946123407807725702626644091036502372545139713
Here is an example of the output using the default values for the factors.
   $ ./rsa-example.py -m "top secret message for bobs eyes only, drink milkshakes"
   Computation Factors and Values
      Short  Long            Value                     Description
        p    prime1          79999987                  # first large prime
        q    prime2          99999989                  # second large prime
        n    bignum          7999997820000143          # p * q
        t    totient         7999997640000168          # φ(n)
        b    bits_per_block  52                        # number of bits in the block
        B    bytes_per_block 6                         # number of bytes in the block
        e    exp_encrypt     65537                     # encryption exponent
        d    exp_decrypt     5288614031051273          # decryption exponent
      Public Key:  {65537, 7999997820000143}
      Private Key: {5288614031051273, 7999997820000143}
   Encrypted Message: 154 0baa25df668c63016a02a10a7e7e1483ea16103e1218663049dbecf90a6c0aa187a6c80b70272211ae2c19b51758498a5a07a883902dc1ae107dcde3b649240e8f12f92958301c3a4448ab95b1
   Decrypted Message: 55 """top secret message for bobs eyes only, drink milkshakes"""
   Original Message:  55 """top secret message for bobs eyes only, drink milkshakes"""
'''
import argparse
import binascii
import inspect
import math
import os
import random
import sys


__version__ = '0.1.0'


def err(msg, xcode=1):
    '''
    Output an error message and exit.
    '''
    lnum = inspect.stack()[1].lineno
    print(f'\033[31mERROR:{lnum}: {msg}\033[0m', file=sys.stderr)
    sys.exit(xcode)


def infov(opts, msg):
    '''
    Output a very verbose message.
    '''
    if opts.verbose >= 1:
        lnum = inspect.stack()[1].lineno
        print(f'INFO:{lnum}: {msg}')


def getopts():
    '''
    Get the command line options.
    '''
    def gettext(string):
        '''
        Convert to upper case to make things consistent.
        '''
        lookup = {
            'usage: ': 'USAGE:',
            'positional arguments': 'POSITIONAL ARGUMENTS',
            'optional arguments': 'OPTIONAL ARGUMENTS',
            'show this help message and exit': 'Show this help message and exit.\n ',
        }
        return lookup.get(string, string)

    argparse._ = gettext  # to capitalize help headers
    base = os.path.basename(sys.argv[0])
    #name = os.path.splitext(base)[0]
    usage = '\n  {0} [OPTIONS] [PATTERNS]'.format(base)
    desc = 'DESCRIPTION:{0}'.format('\n  '.join(__doc__.split('\n')))
    epilog = f'''
EXAMPLES:
    # Example 1: help
    $ {base} --help
    # Example 2: a simple example
    $ {base} -p 79999987 -q 99999989 -e 65537 -v
    # Example 3: an example of small keys with a message
    $ {base} -p 79999987 -q 99999989 -e 65537 -v -m 'top secret message'
    # Example 4: an example with realistically sized keys
    $ {base} -e 65537 \\
        -p 12027524255478748885956220793734512128733387803682075433653899983955179850988797899869146900809131611153346817050832096022160146366346391812470987105415233 \\
        -q 12131072439211271897323671531612440428472427633701410925634549312301964373042085619324197365322416866541017057361365214171711713797974299334871062829803541 \\
        -m 'top secret message for bobs eyes only, only drink milkshakes'
    # Example 5: an example that shows the epilogue
    $ {base} -p 79999987 -q 99999989 -e 65537 -v -m 'top secret message' -l
'''

    afc = argparse.RawTextHelpFormatter
    parser = argparse.ArgumentParser(formatter_class=afc,
                                     description=desc[:-2],
                                     usage=usage,
                                     epilog=epilog + ' \n')

    parser.add_argument('-e', '--encrypt',
                        action='store',
                        type=int,
                        default=65537,
                        metavar=('NUM'),
                        help='''\
The encryption factor.
Default: %(default)s.
''')

    parser.add_argument('-l', '--long',
                        action='store_true',
                        help='''\
Print a long explanation in an epilogue.
''')

    parser.add_argument('-m', '--message-string',
                        action='store',
                        metavar=('STRING'),
                        help='''\
The message string to encrypt/decrypt.
''')

    parser.add_argument('-p', '--prime1',
                        action='store',
                        type=int,
#                        default=12131072439211271897323671531612440428472427633701410925634549312301964373042085619324197365322416866541017057361365214171711713797974299334871062829803541,
                        default=79999987,
                        metavar=('NUM'),
                        help='''\
The first prime.
Default: %(default)s.
''')

    parser.add_argument('-q', '--prime2',
                        action='store',
                        type=int,
#                        default=12131072439211271897323671531612440428472427633701410925634549312301964373042085619324197365322416866541017057361365214171711713797974299334871062829803541,
                        default=99999989,
                        metavar=('NUM'),
                        help='''\
The second prime.
This is required.
''')

    parser.add_argument('--test-decrypt',
                        action='store_true',
                        help='''\
Enable decryption testing during the encrypt process.
This is useful for debugging.
''')

    parser.add_argument('-v', '--verbose',
                        action='count',
                        default=0,
                        help='''\
Output a lot of information about the intermediate steps.
''')

    parser.add_argument('-V', '--version',
                        action='version',
                        version='%(prog)s version {0}'.format(__version__),
                        help='''\
Show program's version number and exit.
''')

    opts = parser.parse_args()
    return opts


def calcd(exp_encrypt, totient):
    '''
    Calculate the d exponent using the extended Euclidean algorithm.
    Returns the d exponent.
    '''
    d_old = 0
    d_new = 1
    r_old = totient
    r_new = exp_encrypt
    while r_new > 0:
        quotient = r_old // r_new
        d_old, d_new = d_new, d_old - quotient * d_new
        r_old, r_new = r_new, r_old - quotient * r_new
    return d_old % totient if r_old == 1 else None


def block_size(bignum):
    '''
    Determine the block size from the modulo range.
    '''
    # Find the block size for figuring out how to chunk the
    # input data.
    log2 = math.log(bignum, 2)
    ival = math.floor(log2)
    bits_per_block = ival if ival < log2 else ival - 1
    bytes_per_block = bits_per_block // 8
    return bytes_per_block, bits_per_block


def determine_rsa_factors(opts):
    '''
    Determine the RSA factors.
    '''
    pnum = opts.prime1
    qnum = opts.prime2
    exp_encrypt = opts.encrypt
    bignum = pnum * qnum
    totient = (pnum - 1) * (qnum - 1)

    # Choose e if necessary.
    if exp_encrypt < 0:
        exp_encrypt = random.randint(3, totient-1)
        while math.gcd(exp_encrypt, totient) != 1:
            exp_encrypt = random.randint(3, totient-1)
    assert math.gcd(exp_encrypt, totient) == 1
    assert 3 <= exp_encrypt < totient

    # Calculate d using the extended Euclidean algorithm.
    exp_decrypt = calcd(exp_encrypt, totient)
    assert exp_decrypt is not None

    # Print factors.
    off = 24  # offset for alignment
    print(f'''
Computation Factors and Values
   Short  Long            {"Value":<{off}}  Description
     p    prime1          {pnum:<{off}}  # first large prime
     q    prime2          {qnum:<{off}}  # second large prime
     n    bignum          {bignum:<{off}}  # p * q
     t    totient         {totient:<{off}}  # \u03c6(n)
     b    bits_per_block  {block_size(bignum)[1]:<{off}}  # number of bits in the block
     B    bytes_per_block {block_size(bignum)[0]:<{off}}  # number of bytes in the block
     e    exp_encrypt     {exp_encrypt:<{off}}  # encryption exponent
     d    exp_decrypt     {exp_decrypt:<{off}}  # decryption exponent
   \033[1mPublic Key:  \033[0m{{{exp_encrypt}, {bignum}}}
   \033[1mPrivate Key: \033[0m{{{exp_decrypt}, {bignum}}}
''')

    # Return the key factors.
    return bignum, exp_encrypt, exp_decrypt


def encrypt(opts, plaintext, bignum, exp_encrypt, exp_decrypt=None):
    '''
    Encrypt the message based on the block size in bytes.
    Padding is determined by bytes_per_block and is very simple.
    Encrypt each bytes_per_block block and then pad at the end.
    '''
    infov(opts, '\033[1mencrypt\033[0m')
    msg_bytes = bytes(plaintext, 'utf-8')
    infov(opts, f'   len(msg_bytes)={len(msg_bytes)}')
    bytes_per_block, _ = block_size(bignum)
    fbs = (1 + bytes_per_block) * 2  # two hex digits per byte
    left_over = 0
    encrypted = []
    for i in range(0, len(msg_bytes), bytes_per_block):
        j = i + bytes_per_block
        chunk = msg_bytes[i:j]
        left_over = bytes_per_block - len(chunk)
        infov(opts, f'   \033[1mchunk=[{i}..{j}) - {chunk}\033[0m')
        infov(opts, f'      fbs={fbs}')
        infov(opts, f'      hex={binascii.hexlify(chunk)}')
        infov(opts, f'      len(chunk)={len(chunk)}')
        infov(opts, f'      bytes_per_block={bytes_per_block}')
        infov(opts, f'      left_over={left_over}')
        if left_over:
            # pad with something, doesn't matter what
            # could be random
            nchunk = bytearray(chunk)
            for _ in range(left_over):
                nchunk.append(ord('x'))
            chunk = bytes(nchunk)
            assert len(nchunk) == bytes_per_block
            infov(opts, f'      chunk={chunk} after padding')

        # Convert the chunk to an integer.
        # Arbitrarily chose big endian because 'big' is fewer letters than 'little'.
        plaintext_chunk = int.from_bytes(chunk, 'big')
        infov(opts, f'      plaintext_chunk={plaintext_chunk}')

        # Encrypt.
        # Use the fast modular exponentiation algorithm provided by python.
        infov(opts, f'      e={exp_encrypt}')
        infov(opts, f'      encrypt() ==> ({plaintext_chunk} ^ {exp_encrypt}) % {bignum}')
        ciphertext_chunk = int(pow(plaintext_chunk, exp_encrypt, bignum))
        infov(opts, f'      ciphertext_chunk={ciphertext_chunk}')

        ciphertext_chunk_hex = f'{ciphertext_chunk:0{fbs}x}'  # string
        infov(opts, f'      ciphertext_chunk_hex={ciphertext_chunk_hex}')
        infov(opts, f'      len(ciphertext_chunk_hex)={len(ciphertext_chunk_hex)}')

        if opts.test_decrypt:
            # Now see if the decrypt works.
            infov(opts, f'      \033[1m** test encryption by decrypting the block\033[0m')
            d_ciphertext_chunk = int(ciphertext_chunk_hex, 16)
            infov(opts, f'      d_ciphertext_chunk={d_ciphertext_chunk}')
            infov(opts, f'      len(d_ciphertext_chunk)={math.log(d_ciphertext_chunk, 10)}')
            assert d_ciphertext_chunk == ciphertext_chunk

            # Use the fast modular exponentiation algorithm provided by python.
            infov(opts, f'      d={exp_decrypt}')
            infov(opts, f'      decrypt() ==> ({d_ciphertext_chunk} ^ {exp_decrypt}) % {bignum}')
            d_plaintext_chunk = int(pow(d_ciphertext_chunk, exp_decrypt, bignum))
            infov(opts, f'      d_plaintext_chunk={d_plaintext_chunk}')
            assert d_plaintext_chunk == plaintext_chunk  # if this passes, it worked

            # Convert the plaintext_chunk integer back to the original bytes format.
            d_chunk = d_plaintext_chunk.to_bytes(bytes_per_block, 'big')
            infov(opts, f'      d_chunk={d_chunk}')
            assert d_chunk == chunk

        # decrypt works, now store the hex ciphertext_chunk.
        encrypted.append(ciphertext_chunk_hex)

    # Add the final padding record.
    infov(opts, f'   \033[1mleft_over={left_over}\033[0m')
    infov(opts, f'      fbs={fbs}')
    padding = left_over.to_bytes(bytes_per_block, 'big')
    infov(opts, f'      bytes_per_block={bytes_per_block}')

    # Convert bytes to integer using big endian.
    padding_ct_chunk = int.from_bytes(padding, 'big')
    infov(opts, f'      padding_ct_chunk={padding_ct_chunk}')

    # Use the fast modular exponentiation algorithm provided by python.
    padding_ct = int(pow(padding_ct_chunk, exp_encrypt, bignum))
    infov(opts, f'      padding_ct={padding_ct}')

    # Convert to a hex string.
    padding_ct_hex = f'{padding_ct:0{fbs}x}'  # string
    infov(opts, f'      padding_ct_hex={padding_ct_hex}')
    infov(opts, f'      len(padding_ct_hex)={len(padding_ct_hex)}')

    if opts.test_decrypt:
        # Now see if the decrypt works.
        infov(opts, f'      \033[1m** test encryption by decrypting the block padding\033[0m')
        d_padding_ct = int(padding_ct_hex, 16)
        infov(opts, f'      d_padding_ct={d_padding_ct}')
        infov(opts, f'      len(d_padding_ct)={math.log(d_padding_ct, 10)}')
        assert d_padding_ct == padding_ct

        # Use the fast modular exponentiation algorithm provided by python.
        infov(opts, f'      d={exp_decrypt}')
        infov(opts, f'      decrypt() ==> ({d_padding_ct} ^ {exp_decrypt}) % {bignum}')
        d_padding_ct_chunk = int(pow(d_padding_ct, exp_decrypt, bignum))
        infov(opts, f'      d_padding_ct_chunk={d_padding_ct_chunk}')
        assert d_padding_ct_chunk == padding_ct_chunk  # if this passes, it worked

        # Convert the plaintext_chunk integer back to the original bytes format.
        d_padding = d_padding_ct_chunk.to_bytes(bytes_per_block, 'big')
        infov(opts, f'      d_padding={d_padding}')
        assert d_padding == padding

    # Add the padding record.
    encrypted.append(padding_ct_hex)
    infov(opts, f'   encrypted = {len(encrypted)} {encrypted}')

    # Return it all as a single string.
    return ''.join(encrypted)


def decrypt(opts, ciphertext, bignum, exp_decrypt):
    '''
    Decrypt the message.
    '''
    infov(opts, '\033[1mdecrypt\033[0m')
    msg_bytes = bytes(ciphertext, 'utf-8')
    infov(opts, f'   len(msg_bytes)={len(msg_bytes)}')
    decrypted = b''
    bytes_per_block, _ = block_size(bignum)
    fbs = (1 + bytes_per_block) * 2  # two hex digits per byte
    last_index = len(msg_bytes) - fbs  # padding block
    for i in range(0, len(msg_bytes), fbs):
        j = i + fbs
        chunk = msg_bytes[i:j]
        infov(opts, f'   \033[1mchunk=[{i}..{j}) - {chunk}\033[0m')
        infov(opts, f'      i={i}, j={j}, last_index={last_index}')
        infov(opts, f'      fbs={fbs}')
        infov(opts, f'      hex={binascii.hexlify(chunk)}')
        infov(opts, f'      len(chunk)={len(chunk)}')
        infov(opts, f'      len(decrypted)={len(decrypted)}')
        infov(opts, f'      bytes_per_block={bytes_per_block}')

        # Decrypt.
        ciphertext_chunk_hex = chunk
        infov(opts, f'      ciphertext_chunk_hex={ciphertext_chunk_hex}')
        infov(opts, f'      len(ciphertext_chunk_hex)={len(ciphertext_chunk_hex)}')

        ciphertext_chunk = int(ciphertext_chunk_hex, 16)
        infov(opts, f'      ciphertext_chunk={ciphertext_chunk}')
        infov(opts, f'      len(ciphertext_chunk)={math.log(ciphertext_chunk, 10)}')

        # Use the fast modular exponentiation algorithm provided by python.
        infov(opts, f'      d={exp_decrypt}')
        infov(opts, f'      decrypt() ==> ({ciphertext_chunk} ^ {exp_decrypt}) % {bignum}')
        plaintext_chunk = int(pow(ciphertext_chunk, exp_decrypt, bignum))
        infov(opts, f'      plaintext_chunk={plaintext_chunk}')

        if i != last_index:
            # Convert the plaintext_chunk integer back to the original bytes format.
            d_chunk = plaintext_chunk.to_bytes(bytes_per_block, 'big')
            infov(opts, f'      d_chunk={d_chunk}')
            infov(opts, f'      len(d_chunk)={len(d_chunk)}')

            # Append to the decrypted list.
            decrypted += d_chunk
        else:
            infov(opts, f'      ** last block padding: {plaintext_chunk}')
            infov(opts, f'      len(decrypted)={len(decrypted)}')
            if plaintext_chunk > 0:
                assert plaintext_chunk < len(decrypted)  # sanity check
                decrypted = decrypted[:-plaintext_chunk]
                infov(opts, f'      len(decrypted)={len(decrypted)}')

    return str(decrypted, 'utf-8')


def epilogue(bignum, exp_encrypt, exp_decrypt, plaintext, encrypted, decrypted):
    '''
    Output the epilogue.
    '''
    print(f'''\033[1mEpilogue\033[0m
Alice wants to send a secure message to Bob while Eve is watching.
She decides to use RSA with the custom padding scheme described below.
Often the message might simply be a key for symmetric encryption
algorithm that she and Bob have agreed to because the RSA algorithm is
slow for large messages but this example shows whatever you entered as
the message.
Alic starts by asking Bob for his public key and receives two numbers:
   1. The encryption exponent: {exp_encrypt}.
   2. The big number that is hard to factor: {bignum}.
Eve can see both of them.
Alice then breaks her message in chunks and RSA encrypts each chunk
using the public key data that Bob sent. The size of the chunks is
determined by the number of bits in the big number.
She then converts the encrypted bytes to their hex representation and
concatenates them to create a long string that can be sent back to
Bob. The size of each block is padded with leading zeros to make sure
that it is constant.
Alice then appends an additional block called the padding block that
tells Bob the number of extra bytes that were used to pad the last
block. That is needed because the message may not fill the last block
so there may be extraneous bytes that could confuse Bob. If the
message fills the last block completely then the padding block
contains the number of zero. The maximum padding value is always one
less than the size of the block (in bytes) so the padding number is
guaranteed to fit.
For this run, the number of bytes in each block is {block_size(bignum)[0]} based on the
fact that there are {block_size(bignum)[1]} bits in the big number that Bob supplied
in the public key. That number of bits rounds up to {block_size(bignum)[0]} bytes. Thus
the largest possible padding value is {block_size(bignum)[0]-1}.
The message that Alice wants to encrypt is {len(plaintext)} bytes:
   """{plaintext}"""
The encrypted message is {len(encrypted)} bytes:
   {encrypted}
Alice sends the encrypted message back to Bob while Eve is watching.
At this point Eve can only see the same public key and the encrypted
message that Alice can see:
   Public Exponent: {exp_encrypt}
   Big Number     : {bignum}
   Encrypted      : {len(encrypted)} {encrypted}
Eve does not have enough information to efficiently decrypt the
message unless the big number is factorable in reasonable time. For
big numbers with more than 331 digits (~2048 bits) factoring becomes
impractical. Note that there are some know attack methods based on
weak values of the exponent or certain traits of the big number but
they will not be discussed here.
Bob receives the message from Alice and proceeds to decrypt it by
reversing the operations that Alice did to encrypt it using his
private key. When finished he sees the original message.
   Private Exponent: {exp_decrypt}  # only Bob has this!
   Public Exponent : {exp_encrypt}
   Big Number      : {bignum}
   Decrypted       : {len(decrypted)} """{decrypted}"""
Details about the RSA key generation, encryption and decryption
algorithm can be found all over the place and they are available for
inspection in the code so they will not be described here. The goal
of this is to give you a feel for the flow with a live example that
implements block handling which is often glossed over.
''')


def main():
    '''
    main
    '''
    opts = getopts()
    bignum, exp_encrypt, exp_decrypt = determine_rsa_factors(opts)
    if opts.message_string:
        plaintext = opts.message_string
        bytes_per_block, _ = block_size(bignum)
        if bytes_per_block < 1:
            err('The number of bytes per block is too small, please increase p or q.')

        encrypted = encrypt(opts, plaintext, bignum, exp_encrypt, exp_decrypt)
        infov(opts, f'encrypted = {len(encrypted)} """{encrypted}"""')

        decrypted = decrypt(opts, encrypted, bignum, exp_decrypt)
        infov(opts, f'decrypted = {len(decrypted)} """{decrypted}"""')
        assert plaintext == decrypted

        print(f'''\
\033[1mEncrypted Message: \033[0m{len(encrypted)} {encrypted}
\033[1mDecrypted Message: \033[0m{len(decrypted)} """{decrypted}"""
\033[1mOriginal Message:  \033[0m{len(plaintext)} """{plaintext}"""
''')
        if opts.long:
            epilogue(bignum, exp_encrypt, exp_decrypt, plaintext, encrypted, decrypted)


if __name__ == '__main__':
    main()
