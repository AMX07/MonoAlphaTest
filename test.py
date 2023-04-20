# mono-alpha cipher

# all the packages needed
import sys
import math
import json
import sys
import random
import time

# global variable
_DEFAULT_ALPHABET = "abcdefghijklmnopqrstuvwxyz"


class Alpha_Invalid(Exception):
    """An exception raised when an alphabet is invalid"""
    pass


class Key_Invalid(Exception):
    """An exception raised when a key is invalid"""
    pass


#### Key class
class CipherKey(object):
    # constructor
    def __init__(self, key, alphabet=_DEFAULT_ALPHABET):

        # Check and store the alphabet
        self._alphabet = self.alphabetCheck(alphabet)

        # Check and store the key
        self._key = self.check_key(key, self._alphabet)

        # Create camel case versions of the key and alphabet
        camel_key = self._upper(key) + key.lower()
        camel_alphabet = self._upper(alphabet) + alphabet.lower()

        # Create encoding and decoding translation tables
        self._encode = str.maketrans(camel_alphabet, camel_key)
        self._decode = str.maketrans(camel_key, camel_alphabet)

    # Check if alphabet is valid
    @staticmethod
    def alphabetCheck(alphabet):
        alphabet = alphabet.lower()
        if len(alphabet) != len(set(alphabet)):
            raise Alpha_Invalid("alphabet characters must be unique")
        return alphabet

    # Check if key is valid
    @staticmethod
    def check_key(key, alphabet):

        key = key.lower()
        key_set = set(key)
        if len(key) != len(key_set):
            raise Key_Invalid("key characters must be unique")

        if len(key) != len(alphabet):
            raise Key_Invalid("key must be as long as the alphabet")
        if key_set != set(alphabet):
            raise Key_Invalid(
                "key must use the same set of characters than the alphabet"
            )
        return key

    # Convert only alphabetic characters to uppercase
    @staticmethod
    def _upper(string):
        return "".join(char.upper() if char.isalpha() else char for char in string)

    # Decode the given ciphertext
    def decode(self, ciphertext):
        return ciphertext.translate(self._decode)

    # Decode a file and write the output to another file
    def decode_file(self, ciphertext_fh=sys.stdin, plaintext_fh=sys.stdout):
        for line in ciphertext_fh:
            plaintext_fh.write(self.decode(line))

    # Encode a file and write the output to another file
    def encode_file(self, plaintext_fh=sys.stdin, ciphertext_fh=sys.stdout):
        for line in plaintext_fh:
            ciphertext_fh.write(self.encode(line))

#### Result class
class Result(object):
    # Constructor
    def __init__(
            self,
            ciphertext=None,
            plaintext=None,
            key=None,
            alphabet=None,
            fitness=0,
            nbr_keys=0,
            nbr_rounds=0,
            keys_per_second=0,
            seconds=0,
    ):
        # Store the parameters as instance variables
        self.ciphertext = ciphertext
        self.plaintext = plaintext
        self.key = key
        self.alphabet = alphabet
        self.fitness = fitness
        self.nbr_keys = nbr_keys
        self.nbr_rounds = nbr_rounds
        self.keys_per_second = keys_per_second
        self.seconds = seconds

    # String representation of the result
    def __str__(self):
        return "key = {}".format(self.key)

#### Breaker class
class CipherBreaker(object):
    # Constructor
    def __init__(self, quadgram_fh):
        # Load quadgram data from the file
        obj = json.load(quadgram_fh)

        # Store the alphabet and other data as instance variables
        self._alphabet = obj["alphabet"]
        self._alphabet_len = len(self._alphabet)
        self._quadgrams = obj["quadgrams"]
        self.key = None

    # Iterate through a file and yield numerical
    @staticmethod
    def _file_iterator(file_fh, alphabet):
        #representation of each character in the alphabet
        trans = {val: key for key, val in enumerate(alphabet.lower())}
        for line in file_fh:
            line = line.lower()
            for char in line:
                val = trans.get(char)
                if val is not None:
                    yield val

    # Iterate through a text and yield numerical representation of each character in the alphabet
    @staticmethod
    def _text_iterator(txt, alphabet):

        trans = {val: key for key, val in enumerate(alphabet.lower())}
        for char in txt.lower():
            val = trans.get(char)
            if val is not None:
                yield val

    # Generate quadgrams based on a given corpus
    @staticmethod
    def generate_quadgrams(corpus_fh, quadgram_fh, alphabet=_DEFAULT_ALPHABET):

        alphabet = CipherKey.alphabetCheck(alphabet)
        if len(alphabet) > 32:
            raise Alpha_Invalid("Alphabet must have less or equal than 32 characters")
        iterator = CipherBreaker._file_iterator(corpus_fh, alphabet)
        quadgram_val = iterator.__next__()
        quadgram_val = (quadgram_val << 5) + iterator.__next__()
        quadgram_val = (quadgram_val << 5) + iterator.__next__()
        quadgrams = [0 for cntr in range(32 * 32 * 32 * 32)]
        for numerical_char in iterator:
            quadgram_val = ((quadgram_val & 0x7FFF) << 5) + numerical_char
            quadgrams[quadgram_val] += 1

        # Normalize the quadgrams
        quadgram_sum = sum(quadgrams)
        quadgram_min = 10000000
        for val in quadgrams:
            if val:
                quadgram_min = min(quadgram_min, val)
        offset = math.log(quadgram_min / 10 / quadgram_sum)

        norm = 0
        for idx, val in enumerate(quadgrams):
            if val:
                prop = val / quadgram_sum
                new_val = math.log(prop) - offset
                quadgrams[idx] = new_val
                norm += prop * new_val

        for idx, val in enumerate(quadgrams):
            quadgrams[idx] = round(quadgrams[idx] / norm * 1000)

        # Just for curiosity: determine the most frequent quadgram
        max_idx = quadgrams.index(max(quadgrams))
        max_val = quadgrams[max_idx]
        # now construct the ASCII representation from the index
        max_chars = []
        index = max_idx
        for _ in range(4):
            max_chars = [alphabet[index & 0x1F]] + max_chars
            index >>= 5

        # Save quadgram data to a file
        json.dump(
            {
                "alphabet": alphabet,
                "nbr_quadgrams": quadgram_sum,
                "most_frequent_quadgram": "".join(max_chars),
                "max_fitness": max_val,
                "average_fitness": sum(quadgrams) / (len(alphabet) ** 4),
                "quadgrams": quadgrams,
            },
            quadgram_fh,
            indent=0,
        )

    # Calculate the fitness of a given text or file
    def _calc_fitness(self, iterator):

        try:
            quadgram_val = iterator.__next__()
            quadgram_val = (quadgram_val << 5) + iterator.__next__()
            quadgram_val = (quadgram_val << 5) + iterator.__next__()
        except StopIteration:
            raise ValueError(
                "More than three characters from the given alphabet are required"
            )

        fitness = 0
        nbr_quadgrams = 0
        quadgrams = self._quadgrams
        for numerical_char in iterator:
            quadgram_val = ((quadgram_val & 0x7FFF) << 5) + numerical_char
            fitness += quadgrams[quadgram_val]
            nbr_quadgrams += 1
        if nbr_quadgrams == 0:
            raise ValueError(
                "More than three characters from the given alphabet are required"
            )
        return fitness / nbr_quadgrams / 10

    def calc_fitness_file(self, cleartext_fh=sys.stdin):

        return self._calc_fitness(CipherBreaker._file_iterator(cleartext_fh, self._alphabet))

    def calc_fitness(self, txt):

        return self._calc_fitness(CipherBreaker._text_iterator(txt, self._alphabet))

    def _hill_climbing(self, key, cipher_bin, char_positions):

        plaintext = [key.index(idx) for idx in cipher_bin]
        quadgram = self._quadgrams
        key_len = self._alphabet_len
        nbr_keys = 0
        max_fitness = 0
        better_key = True
        while better_key:
            better_key = False
            for idx1 in range(key_len - 1):
                for idx2 in range(idx1 + 1, key_len):
                    ch1 = key[idx1]
                    ch2 = key[idx2]
                    for idx in char_positions[ch1]:
                        plaintext[idx] = idx2
                    for idx in char_positions[ch2]:
                        plaintext[idx] = idx1
                    nbr_keys += 1
                    tmp_fitness = 0
                    quad_idx = (plaintext[0] << 10) + (plaintext[1] << 5) + plaintext[2]
                    for char in plaintext[3:]:
                        quad_idx = ((quad_idx & 0x7FFF) << 5) + char
                        tmp_fitness += quadgram[quad_idx]
                    if tmp_fitness > max_fitness:
                        max_fitness = tmp_fitness
                        better_key = True
                        key[idx1] = ch2
                        key[idx2] = ch1
                    else:
                        for idx in char_positions[ch1]:
                            plaintext[idx] = idx1
                        for idx in char_positions[ch2]:
                            plaintext[idx] = idx2
        return max_fitness, nbr_keys

    def break_cipher(self, ciphertext, max_rounds=10000, consolidate=3):

        if not (1 <= max_rounds <= 10000):
            raise ValueError("maximum number of rounds not in the valid range 1..10000")
        if not (1 <= consolidate <= 30):
            raise ValueError("consolidate parameter out of valid range 1..30")
        start_time = time.time()
        nbr_keys = 0
        cipher_bin = [
            char for char in CipherBreaker._text_iterator(ciphertext, self._alphabet)
        ]
        if len(cipher_bin) < 4:
            raise ValueError("ciphertext is too short")

        char_positions = []
        for idx in range(len(self._alphabet)):
            char_positions.append([i for i, x in enumerate(cipher_bin) if x == idx])

        key_len = len(self._alphabet)
        local_maximum, local_maximum_hit = 0, 1
        key = [idx for idx in range(key_len)]
        best_key = key.copy()
        for round_cntr in range(max_rounds):
            random.shuffle(key)
            fitness, tmp_nbr_keys = self._hill_climbing(key, cipher_bin, char_positions)
            nbr_keys += tmp_nbr_keys
            if fitness > local_maximum:
                local_maximum = fitness
                local_maximum_hit = 1
                best_key = key.copy()
            elif fitness == local_maximum:
                local_maximum_hit += 1
                if local_maximum_hit == consolidate:
                    break
        key_str = "".join([self._alphabet[x] for x in best_key])
        self.key = CipherKey(key_str, alphabet=self._alphabet)
        seconds = time.time() - start_time
        return Result(
            ciphertext=ciphertext,
            plaintext=self.key.decode(ciphertext),
            key=key_str,
            alphabet=self._alphabet,
            fitness=local_maximum / (len(cipher_bin) - 3) / 10,
            nbr_keys=nbr_keys,
            nbr_rounds=round_cntr,
            keys_per_second=round(nbr_keys / seconds, 3),
            seconds=seconds,
        )


###############################################################################################
#driving code

# Define your ciphertext here
ciphertext = "Zggp zg  vozi Eqtlqk eohitk (gk Eqtlqk egrt), q lioyz eohitk, gft gy zit dglz tqln qfr dglz yqdgxl tfeknhzogf lnlztdl, ziqz xltl zit lxwlzozxzogf gy q ptzztk wn qfgzitk gft yxkzitk of zit qphiqwtz."

# Load the quadgram file;
quadgram_file_path = "EN.json"

# Initialize the Breaker object with the quadgram file
with open(quadgram_file_path) as quadgram_fh:
    breaker = CipherBreaker(quadgram_fh)

# Break the cipher and obtain the result
result = breaker.break_cipher(ciphertext)

# Print the decrypted plaintext
print(result.plaintext)
