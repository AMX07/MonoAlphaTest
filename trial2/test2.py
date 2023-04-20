from pycipher import SimpleSubstitution as SimpleSub
import time
import random
import re
from math import log10


class nscore(object):
    def __init__(self, ngram_file, sep=' '):
        self.ngram_dict = {}
        with open(ngram_file, 'r') as f:
            for line in f:
                ngram, count = line.split(sep)
                self.ngram_dict[ngram] = int(count)
        self.ngram_len = len(ngram)
        self.total_count = sum(self.ngram_dict.values())
        # calculate log probabilities
        for ngram in self.ngram_dict.keys():
            self.ngram_dict[ngram] = log10(float(self.ngram_dict[ngram]) / self.total_count)
        self.min_prob = log10(0.01 / self.total_count)

    def compute_score(self, text):
        ''' compute the score of text '''
        current_score = 0
        ngram_prob = self.ngram_dict.__getitem__
        for i in range(len(text) - self.ngram_len + 1):
            if text[i:i + self.ngram_len] in self.ngram_dict:
                current_score += ngram_prob(text[i:i + self.ngram_len])
            else:
                current_score += self.min_prob
        return current_score


fitness = nscore('quadgrams.txt')  # load our quadgram statistics

cipher_text = 'Gfpn zit higzgukqhil gf zit dqfztphotet ktqppn ligvtr igv dxei zodt iqr hqlltr. Ztf ntqkl qug, zitkt iqr wttf pgzl gy hoezxktl gy viqz pggatr poat q pqkut hofa wtqei wqpp vtqkofu royytktfz-egpgktr wgfftzl - wxz Rxrptn Rxklptn vql fg pgfutk q wqwn, qfr fgv zit higzgukqhil ligvtr q pqkut wpgfr wgn korofu iol yoklz woenept, gf q eqkgxltp qz zit yqok, hpqnofu q egdhxztk uqdt vozi iol yqzitk, wtofu ixuutr qfr aolltr wn iol dgzitk. Zit kggd itpr fg louf qz qpp ziqz qfgzitk wgn poctr of zit igxlt, zgg.'
special_char_positions = [(pos, char) for pos, char in enumerate(cipher_text) if not char.isalpha()]
cipher_text = re.sub('[^A-Z]', '', cipher_text.upper())

alphabet_key = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
best_score = -99e9
initial_score, initial_key = best_score, alphabet_key[:]

start_time = time.time()
iteration = 0
while 1:
    iteration += 1
    random.shuffle(initial_key)
    decrypted_text = SimpleSub(initial_key).decipher(cipher_text)
    initial_score = fitness.compute_score(decrypted_text)
    local_count = 0
    while local_count < 1000:
        idx1 = random.randint(0, 25)
        idx2 = random.randint(0, 25)
        child_key = initial_key[:]
        #swap two characters in the child_key
        child_key[idx1], child_key[idx2] = child_key[idx2], child_key[idx1]
        decrypted_text = SimpleSub(child_key).decipher(cipher_text)
        score = fitness.compute_score(decrypted_text)
        # if the child_key was better, replace the parent_key with it
        if score > initial_score:
            initial_score = score
            initial_key = child_key[:]
            local_count = 0
        local_count += 1

        # Check if elapsed time is more than 10 seconds
        elapsed_time = time.time() - start_time
        if elapsed_time > 10:
            break

    # keep track of best score seen so far
    if initial_score > best_score:
        best_score, alphabet_key = initial_score, initial_key[:]
        #print('\nbest score so far:', best_score, 'on iteration', iteration)
        simple_sub_cipher = SimpleSub(alphabet_key)
        #print('best key: ' + ''.join(alphabet_key))
        final_decrypted_text = simple_sub_cipher.decipher(cipher_text)
        #print('plaintext: ' + final_decrypted_text)
        #print(local_count)

    # If the loop was stopped due to the time constraint, print the final result
    if elapsed_time > 20:
        print(final_decrypted_text)
        #for pos in space_positions:
        #    final_decrypted_text = final_decrypted_text[:pos] + ' ' + final_decrypted_text[pos:]
        # Add special characters back into the final decrypted text
        for pos, char in special_char_positions:
            final_decrypted_text = final_decrypted_text[:pos] + char + final_decrypted_text[pos:]

        print('Final plaintext: ' + final_decrypted_text)
        break

'''Harry potter text works perfectly'''
# Ftqkpn ztf ntqkl iqr hqlltr lofet zit Rxklptnl iqr vgatf xh zg yofr zitok fthitv gf zit ykgfz lzth, wxz Hkoctz Rkoct iqr iqkrpn eiqfutr qz qpp. Zit lxf kglt gf zit lqdt zorn ykgfz uqkrtfl qfr poz xh zit wkqll fxdwtk ygxk gf zit Rxklptnl' ykgfz rggk; oz ekthz ofzg zitok pocofu kggd, vioei vql qpdglz tmqezpn zit lqdt ql oz iqr wttf gf zit fouiz vitf Dk. Rxklptn iqr lttf ziqz yqztyxp ftvl kthgkz qwgxz zit gvpl

#Gfpn zit higzgukqhil gf zit dqfztphotet ktqppn ligvtr igv dxei zodt iqr hqlltr. Ztf ntqkl qug, zitkt iqr wttf pgzl gy hoezxktl gy viqz pggatr poat q pqkut hofa wtqei wqpp vtqkofu royytktfz-egpgktr wgfftzl - wxz Rxrptn Rxklptn vql fg pgfutk q wqwn, qfr fgv zit higzgukqhil ligvtr q pqkut wpgfr wgn korofu iol yoklz woenept, gf q eqkgxltp qz zit yqok, hpqnofu q egdhxztk uqdt vozi iol yqzitk, wtofu ixuutr qfr aolltr wn iol dgzitk. Zit kggd itpr fg louf qz qpp ziqz qfgzitk wgn poctr of zit igxlt, zgg.


#cipher #1: Q pgfu zodt qug of q uqpqmn yqk, yqk qvqn qfr wn zit Lzqk Vqkl pgug vioei ktetrtl zgvqkr q etfzkqp hgofz gf zit lekttf wtygkt rolqhhtqkofu. Zit ekqvp ztmz, vioei rtlekowtl zit wqealzgkn qfr egfztmz gy zit yopd, zitf ktetrtl zgvqkr q iouitk hgofz of ktpqzogf zg zit lekttf qfr vozi qf qhhqktfz tyytez gy rolqhhtqkofu of zit rolzqfet

#cipher #2 Zggp zg  vozi Eqtlqk eohitk (gk Eqtlqk egrt), q lioyz eohitk, gft gy zit dglz tqln qfr dglz yqdgxl tfeknhzogf lnlztdl, ziqz xltl zit lxwlzozxzogf gy q ptzztk wn qfgzitk gft yxkzitk of zit qphiqwtz
