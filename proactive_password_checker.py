import mmh3
import xxhash
import bitarray
import sys
from fnvhash import fnv1a_32

N = 1024
INPUT_FILE_ENCODING = 'iso-8859-1'


class ProactivePasswordChecker:
    def __init__(self, dictionary_file_name, candidate_file_name, output_file_name):
        self.dictionary_file_name = dictionary_file_name
        self.candidate_file_name = candidate_file_name
        self.output_file_name = output_file_name
        self.hash_table = self.initialize_hash_table()

    def initialize_hash_table(self):
        hash_table = bitarray.bitarray(N)
        hash_table.setall(0)
        return hash_table

    def proactive_password_check(self):
        self.set_bloom_filter_using_dictionary()
        self.write_output_file_name_using_bloom_filter()

    def set_bloom_filter_using_dictionary(self):
        dictionary_file = open(self.dictionary_file_name, 'r', encoding=INPUT_FILE_ENCODING)
        lines = dictionary_file.readlines()
        for word in lines:
            self.set_bloom_filter(word.strip())
        dictionary_file.close()

    def write_output_file_name_using_bloom_filter(self):
        candidate_file = open(self.candidate_file_name, 'r', encoding=INPUT_FILE_ENCODING)
        lines = candidate_file.readlines()
        output_file = open(self.output_file_name, 'w')
        for word in lines:
            is_accepted = self.get_bloom_filter(word.strip())


            data = f"{word.strip()} {is_accepted}\n"
            output_file.write(data)
        output_file.close()
        candidate_file.close()

    def set_bloom_filter(self, word):
        mm3_index = mmh3.hash(word) % N
        xxhash_index = xxhash.xxh32(word).intdigest() % N
        fnv1a_32_index = fnv1a_32(bytes(word, encoding='utf-8')) % N
        self.hash_table[mm3_index] = 1
        self.hash_table[xxhash_index] = 1
        self.hash_table[fnv1a_32_index] = 1

    def get_bloom_filter(self, word):
        mm3_index = mmh3.hash(word) % N
        xxhash_index = xxhash.xxh32(word).intdigest() % N
        fnv1a_32_index = fnv1a_32(bytes(word, encoding='utf-8')) % N
        is_accepted = 1

        if self.hash_table[mm3_index] == 1 and self.hash_table[xxhash_index] == 1 and self.hash_table[
            fnv1a_32_index] == 1:
            is_accepted = 0

        return is_accepted


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Insufficient arguments. please input input_file_name & candidate_file_name & output_file_name")
        sys.exit()
    bloom_filter = ProactivePasswordChecker(sys.argv[1], sys.argv[2], sys.argv[3])
    bloom_filter.proactive_password_check()
