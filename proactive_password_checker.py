import mmh3
import xxhash
import bitarray
import sys
from fnvhash import fnv1a_32

N = 1024


class ProactivePasswordChecker:
    def __init__(self, input_file_name, output_file_name):
        self.input_file_name = input_file_name
        self.output_file_name = output_file_name
        self.hash_table = self.initialize_hash_table()

    def initialize_hash_table(self):
        hash_table = bitarray.bitarray(N)
        hash_table.setall(0)
        return hash_table

    def read_files_and_handle(self):
        input_file_encoding = 'iso-8859-1'
        input_file = open(self.input_file_name, 'r', encoding=input_file_encoding)
        lines = input_file.readlines()
        output_file = open(self.output_file_name, 'w')
        for word in lines:
            is_accepted = self.do_bloom_filter(word)

            data = f"{word.strip()} {is_accepted} \n"
            output_file.write(data)
        output_file.close()
        input_file.close()

    def do_bloom_filter(self, word):
        mm3_index = mmh3.hash(word) % N
        xxhash_index = xxhash.xxh32(word).intdigest() % N
        fnv1a_32_index = fnv1a_32(bytes(word, encoding='utf-8')) % N

        is_accepted = 1

        if self.hash_table[mm3_index] == 1 and self.hash_table[xxhash_index] == 1 and self.hash_table[
            fnv1a_32_index] == 1:
            is_accepted = 0

        self.hash_table[mm3_index] = 1
        self.hash_table[xxhash_index] = 1
        self.hash_table[fnv1a_32_index] = 1
        return is_accepted


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Insufficient arguments. please input input_file_name & output_file_name")
        sys.exit()
    bloom_filter = ProactivePasswordChecker(sys.argv[1], sys.argv[2])
    bloom_filter.read_files_and_handle()
