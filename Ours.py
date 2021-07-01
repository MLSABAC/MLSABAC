from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc, Input, Output
from collections import defaultdict
from Zeropoly import Zero_poly
from ascon import *
from openpyxl import Workbook
from charm.core.engine.util import serializeDict,objectToBytes,serializeObject

# type annotations'
pk_t = { 'g_2':G1, 'h_i':G2, 'e_gg_alpha':GT}
mk_t = {'alpha':ZR, 'g':G1 }
dk_t = { 'dk':G1, 'B': str }
ct_t = { 'C':bytes, 'nonce':bytes, 'C1':G1, 'C2':G2, 'policy':str }
tk_t = { 'tk':G1, 'Cp':G1, 'B': str }
sec_t = { 'mu':ZR }
pd_t = { 'pd': GT, 'nonce':bytes, 'C':bytes, 'policy': str }
debug = False
class CPabe_SP21(ABEnc):
    def __init__(self, groupObj):
        ABEnc.__init__(self)
        global util, group
        util = SecretUtil(groupObj, verbose=False)
        group = groupObj
    
    @Output(pk_t, mk_t)    
    def setup(self,uni_size):
        g, h, alpha = group.random(G1), group.random(G2), group.random(ZR)
        g.initPP(); h.initPP()
        g_2 = g ** (alpha**2)
        e_gg_alpha = pair(g,h)**alpha
        h_i= {}
        for j in range(uni_size+1):
            h_i[j] = h ** (alpha ** j)
        pk = {'g_2':g_2, 'h_i':h_i, 'e_gg_alpha':e_gg_alpha}
        mk = {'alpha':alpha, 'g':g }
        return (pk, mk)

    @Input(pk_t, mk_t, list, list)
    @Output(dk_t)
    def keygen(self, pk, mk, B, U):
        S= list(set(U) - set(B)); Zerop=1
        for attrs in S:
            Zerop *= mk['alpha'] + group.hash(attrs, ZR) 
        dk = mk['g'] ** (1/Zerop)
        return { 'dk':dk, 'B':B }
    
    @Input(pk_t, bytes, list, list)
    @Output(ct_t)
    def encrypt(self, pk, mes, P, U): 
        a=[]; C2=1
        Com_set= list(set(U) - set(P))
        for attrs in Com_set:
            a.append(group.hash(attrs, ZR))
        (indices,coeff_mult)=Zero_poly(a,len(a)-1,[0],[1])
        Coeffs=list(reversed(coeff_mult))
        for i in range(len(indices)):
            C2*= (pk['h_i'][i+1] ** Coeffs[i])
        r = group.random(ZR)     
        C = pk['e_gg_alpha'] ** r
        C1 = pk['g_2'] ** (-r)
        C2 = C2 ** r
        C = objectToBytes(C, group)
        pls = objectToBytes(P, group)
        H = ascon_hash(pls+C, "Ascon-Hash")
        nonce = get_random_bytes(16)
        key = H[8:24]
        associatedata = H[24:]
        output = ascon_encrypt(key,nonce,associatedata,mes,variant="Ascon-128")
        return { 'C':output, 'nonce':nonce, 'C1':C1, 'C2':C2, 'policy':P}
    
    @Input(dk_t, ct_t)
    @Output(tk_t, sec_t)
    def Tgen(self, dk, ct):
        mu = group.random(ZR)
        Tk = dk['dk'] ** (mu)
        Cp = ct['C1'] ** (mu)
        tk = { 'tk':Tk, 'Cp':Cp, 'B': dk['B'] }
        sec={'mu':mu}
        return (tk, sec)

    @Input(pk_t, tk_t, ct_t)
    @Output(pd_t)
    def Pardecrypt(self, pk, tk, ct):
        A=list(set(tk['B'])-set(ct['policy']))
        a=[]; z=1
        for attrs in A:
            a.append(group.hash(attrs, ZR))
        (indices,coeff_mult)=Zero_poly(a,len(a)-1,[0],[1])
        Coeffs=list(reversed(coeff_mult))
        for i in range(len(indices)-1):
            z*= pk['h_i'][i] ** Coeffs[i+1]
        pd=(pair(tk['Cp'],z) * pair(tk['tk'],ct['C2'])) ** (1/Coeffs[0])
        return {'pd':pd, 'nonce':ct['nonce'], 'C': ct['C'], 'policy': ct['policy']}

    @Input(pd_t, sec_t)
    @Output(bytes)
    def decrypt(self, pd, sec):
        C = (pd['pd']**(1/sec['mu']))
        Cb = objectToBytes(C, group)
        pls = objectToBytes(pd['policy'], group)
        H = ascon_hash(pls+Cb, "Ascon-Hash")
        key = H[8:24]
        associatedata = H[24:]
        (mprime) = ascon_decrypt(key,pd['nonce'],associatedata, pd['C'], variant="Ascon-128")
        return (mprime)



groupObj = PairingGroup('SS512')
cpabe = CPabe_SP21(groupObj)

def start_bench(group):
    group.InitBenchmark()
    group.StartBenchmark(["RealTime"])

def end_bench(group):
    group.EndBenchmark()
    benchmarks = group.GetGeneralBenchmarks()
    real_time = benchmarks['RealTime']
    return real_time

def main(n):   
    U = ['ONE', 'TWO', 'THREE', 'FOUR', 'FIVE', 'SIX', 'SEVEN', 'EIGHT', 'NINE'] * n
    B = ['ONE', 'TWO', 'THREE', 'FOUR', 'FIVE', 'SIX'] * n
    P = ['ONE', 'TWO', 'THREE', 'SIX'] * n
    result= [n*10,n*5,n*3]
    setup_time=0
    for i in range(10):
        start_bench(groupObj)
        (pk, mk) = cpabe.setup(len(U))
        setup_time += end_bench(groupObj)
    result.append(setup_time*100)

    keygen_time=0
    for i in range(10):
        start_bench(groupObj)
        dk = cpabe.keygen(pk, mk, B, U)
        keygen_time += end_bench(groupObj)
    result.append(keygen_time*100)
    key_size = sum([len(x) for x in serializeDict(dk, groupObj).values()])
    result.append(key_size)
    
    msg = b"This is the test ascon-128 for MLS-ABAC paper"
    encrypt_time=0
    for i in range(10):
        start_bench(groupObj)
        ct = cpabe.encrypt(pk, msg, P, U)
        encrypt_time += end_bench(groupObj)
    result.append(encrypt_time*100)
    cipher_size = len(serializeObject(ct['C1'], groupObj)) + len(serializeObject(ct['C2'], groupObj)) + len(ct['C']) + len(ct['nonce']) + len(serializeObject(ct['policy'], groupObj))
    print(cipher_size)
    result.append(cipher_size)

    tkgen_time=0
    for i in range(10):
        start_bench(groupObj)
        (tk,sec) = cpabe.Tgen(dk, ct)
        tkgen_time += end_bench(groupObj)
    result.append(tkgen_time*100)
    token_size = sum([len(x) for x in serializeDict(tk, groupObj).values()])
    result.append(token_size)

    pardecrypt_time=0
    for i in range(10):
        start_bench(groupObj)
        pd = cpabe.Pardecrypt(pk, tk, ct)
        pardecrypt_time += end_bench(groupObj)
    result.append(pardecrypt_time*100)

    decrypt_time=0
    for i in range(10):
        start_bench(groupObj)
        (mprime) = cpabe.decrypt(pd, sec)
        decrypt_time += end_bench(groupObj)
    result.append(decrypt_time*100)
    return result

book = Workbook()
data = book.active
title = ["n","b","p","setup_time", "keygen_time", "key_size" ,"encrypt_time", "Cipher_size", "tkgen_time", "token_size", "pardecrypt_time", "Decryption_time"]
data.append(title)

for n in range(1,202,10):
    data.append(main(n))
    print(n)

book.save("Result200.xlsx")