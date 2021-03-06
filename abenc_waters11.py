'''
Brent Waters (Pairing-based)
 
| From: "Ciphertext-Policy Attribute-Based Encryption: An Expressive, Efficient, and Provably Secure Realization", Appendix C.
| Published in: 2008
| Available from: http://eprint.iacr.org/2008/290.pdf
| Notes: Security Assumption: parallel q-DBDHE. The sole disadvantage of this scheme is the high number of pairings
| that must be computed during the decryption process (2 + N) for N attributes mathing in the key.

* type:            ciphertext-policy attribute-based encryption (public key)
* setting:        Pairing

:Authors:    J Ayo Akinyele
:Date:            11/2010
'''
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc
from openpyxl import Workbook
from charm.core.engine.util import serializeDict,objectToBytes
debug = False
class CPabe09(ABEnc):
    """
    >>> from charm.toolbox.pairinggroup import PairingGroup,GT
    >>> group = PairingGroup('SS512')
    >>> cpabe = CPabe09(group)
    >>> msg = group.random(GT)
    >>> (master_secret_key, master_public_key) = cpabe.setup()
    >>> policy = '((ONE or THREE) and (TWO or FOUR))'
    >>> attr_list = ['THREE', 'ONE', 'TWO']
    >>> secret_key = cpabe.keygen(master_public_key, master_secret_key, attr_list)
    >>> cipher_text = cpabe.encrypt(master_public_key, msg, policy)
    >>> decrypted_msg = cpabe.decrypt(master_public_key, secret_key, cipher_text)
    >>> decrypted_msg == msg
    True
    """
    
    def __init__(self, groupObj):
        ABEnc.__init__(self)
        global util, group
        util = SecretUtil(groupObj, debug)        
        group = groupObj
                        
    def setup(self):
        g1, g2 = group.random(G1), group.random(G2)
        alpha, a = group.random(), group.random()        
        e_gg_alpha = pair(g1,g2) ** alpha
        msk = {'g1^alpha':g1 ** alpha, 'g2^alpha':g2 ** alpha}        
        pk = {'g1':g1, 'g2':g2, 'e(gg)^alpha':e_gg_alpha, 'g1^a':g1 ** a, 'g2^a':g2 ** a}
        return (msk, pk)
    
    def keygen(self, pk, msk, attributes):        
        t = group.random()
        K = msk['g2^alpha'] * (pk['g2^a'] ** t)
        L = pk['g2'] ** t
        k_x = [group.hash(s, G1) ** t for s in attributes]
        
        K_x = {}
        for i in range(0, len(k_x)):
            K_x[ attributes[i] ] = k_x[i]    

        key = { 'K':K, 'L':L, 'K_x':K_x, 'attributes':attributes }
        return key
    
    def encrypt(self, pk, M, policy_str):
        # Extract the attributes as a list
        policy = util.createPolicy(policy_str)        
        p_list = util.getAttributeList(policy)
        s = group.random()
        C_tilde = (pk['e(gg)^alpha'] ** s) * M
        C_0 = pk['g1'] ** s
        C, D = {}, {}
        secret = s
        shares = util.calculateSharesList(secret, policy)

        # ciphertext
        for i in range(len(p_list)):
            r = group.random()
            if shares[i][0] == p_list[i]:
               attr = shares[i][0].getAttribute() 
               C[ p_list[i] ] = ((pk['g1^a'] ** shares[i][1]) * (group.hash(attr, G1) ** -r))
               D[ p_list[i] ] = (pk['g2'] ** r)
        
        if debug: print("SessionKey: %s" % C_tilde)
        return { 'C0':C_0, 'C':C, 'D':D , 'C_tilde':C_tilde, 'policy':policy_str, 'attribute':p_list }
    
    def decrypt(self, pk, sk, ct):
        policy = util.createPolicy(ct['policy'])
        pruned = util.prune(policy, sk['attributes'])
        if pruned == False:
            return False
        coeffs = util.getCoefficients(policy)
        numerator = pair(ct['C0'], sk['K'])
        
        # create list for attributes in order...
        k_x, w_i = {}, {}
        for i in pruned:
            j = i.getAttributeAndIndex()
            k = i.getAttribute()
            k_x[ j ] = sk['K_x'][k]
            w_i[ j ] = coeffs[j]
            #print('Attribute %s: coeff=%s, k_x=%s' % (j, w_i[j], k_x[j]))
            
        C, D = ct['C'], ct['D']
        denominator = 1
        for i in pruned:
            j = i.getAttributeAndIndex()
            denominator *= ( pair(C[j] ** w_i[j], sk['L']) * pair(k_x[j] ** w_i[j], D[j]) )   
        return ct['C_tilde'] / (numerator / denominator)

    #Get the eliptic curve with the bilinear mapping feature needed.

def start_bench(group):
    group.InitBenchmark()
    group.StartBenchmark(["RealTime"])

def end_bench(group):
    group.EndBenchmark()
    benchmarks = group.GetGeneralBenchmarks()
    real_time = benchmarks['RealTime']
    return real_time





def main(n):
    pol = '((four or three) and (three or one)) and' * n
    attr_list = ['ONE', 'TWO', 'THREE', 'FOUR', 'FIVE', 'SIX', 'SEVEN', 'EIGHT', 'NINE', 'TEN'] * n
    result= [n*10,n*5,n*3]
    groupObj = PairingGroup('SS512')
    cpabe = CPabe09(groupObj)

    setup_time=0
    for i in range(10):
        start_bench(groupObj)
        (msk, pk) = cpabe.setup()
        setup_time += end_bench(groupObj)
    result.append(setup_time*100)


    

    if debug: print('Acces Policy: %s' % pol)
    if debug: print('User credential list: %s' % attr_list)
    m = groupObj.random(GT)
    keygen_time=0
    for i in range(10):
        start_bench(groupObj)
        cpkey = cpabe.keygen(pk, msk, attr_list)
        keygen_time += end_bench(groupObj)
    result.append(keygen_time*100)
    key_size = sum([len(x) for x in serializeDict(cpkey, groupObj).values()])
    result.append(key_size)


 
    if debug: print("\nSecret key: %s" % attr_list)
    if debug:groupObj.debug(cpkey)
    encrypt_time=0
    for i in range(10):
        start_bench(groupObj)
        cipher = cpabe.encrypt(pk, m, pol)
        encrypt_time += end_bench(groupObj)
    result.append(encrypt_time*100)
    cipher_size = sum([len(x) for x in serializeDict(cipher, groupObj).values()])
    result.append(cipher_size)

    

    if debug: print("\nCiphertext...")
    if debug:groupObj.debug(cipher)
    decrypt_time=0
    for i in range(10):
        start_bench(groupObj)
        orig_m = cpabe.decrypt(pk, cpkey, cipher)
        decrypt_time += end_bench(groupObj)
    result.append(decrypt_time*100)


    assert m == orig_m, 'FAILED Decryption!!!'
    if debug: print('Successful Decryption!')
    del groupObj
    
    return result

book=Workbook()
data=book.active
title=["n","b","p","setup_time", "keygen_time", "key_size" ,"encrypt_time", "Cipher_size", "Decryption_time"]
data.append(title)

for n in range(1,202,10):
    data.append(main(n))
    print(n)

book.save("Result_waters09.xlsx")