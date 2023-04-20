from pycipher import SimpleSubstitution as SimpleSub
import random
import re
from math import log10


######################################
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


#######################################################
fitness = nscore('quadgrams.txt')  # load our quadgram statistics

cipher_text = 'Q pgfu zodt qug of q uqpqmn yqk, yqk qvqn qfr wn zit Lzqk Vqkl pgug vioei ktetrtl zgvqkr q etfzkqp hgofz gf zit lekttf wtygkt rolqhhtqkofu. Zit ekqvp ztmz, vioei rtlekowtl zit wqealzgkn qfr egfztmz gy zit yopd, zitf ktetrtl zgvqkr q iouitk hgofz of ktpqzogf zg zit lekttf qfr vozi qf qhhqktfz tyytez gy rolqhhtqkofu of zit rolzqfet'
space_positions = [pos for pos, char in enumerate(cipher_text) if char == ' ']
cipher_text = re.sub('[^A-Z]', '', cipher_text.upper())

alphabet_key = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
best_score = -99e9
initial_score, initial_key = best_score, alphabet_key[:]

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
            # modification for spaces
            for pos in space_positions:
                decrypted_text = decrypted_text[:pos] + ' ' + decrypted_text[pos:]
            local_count = 0
        local_count += 1
    # keep track of best score seen so far
    if initial_score > best_score:
        best_score, alphabet_key = initial_score, initial_key[:]
        print('\nbest score so far:', best_score, 'on iteration', iteration)
        simple_sub_cipher = SimpleSub(alphabet_key)
        print('best key: ' + ''.join(alphabet_key))
        print('plaintext: ' + simple_sub_cipher.decipher(cipher_text))

