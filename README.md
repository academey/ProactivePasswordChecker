
# How to run the program
```console
>> pip install
# Ex) python proactive_password_checker.py dictionary.txt test_candidate.txt Bloomchecked.txt 
>> python proactive_password_checker.py [dictionary_file_name] [candidate_file_name] [output_file_name] 
``` 

# Description
Bloom Filter is a filter to determine the possibility of a specific value.
If the index of the value hashed a particular value to mod N has already been painted, it means that the value may already exist.
Conversely, if the indexes of the value are all empty values, it means that they do not exist. Therefore, it can be accepted.



# the reason for choosing such hash functions
The hash functions used in a Bloom filter should be independent and uniformly distributed. 
Examples of fast, simple hashes that are independent enough3 include murmur, xxHash, the fnv series of hashes, and HashMix.
So I chose xxhash, murmur, and fnv as hash functions.
