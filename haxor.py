import sys
from array import array
import base64
import hashlib
from time import time
from itertools import product, combinations

# NOTE: THIS SCRIPT WAS MODIFIED TO WORK WITH PYTHON 3, NOT 2.7

def haxor(password, limit):
    passwords = []

    char_replacements = {
       'a': ['a', '4'],
       'e': ['e', '3'],
       'i': ['i', '1'],
       't': ['t', '7'],
       'o': ['o', '0']
    }

    replacement_pos = [i for i, char in enumerate(password) if char in char_replacements]
    
    for num_replacements in range(1, min(limit, len(replacement_pos)) + 1):
        for positions in combinations(replacement_pos, num_replacements):
           
            options = [
                char_replacements[char] if i in positions else [char]
                for i, char in enumerate(password)
            ]
            
            possibilities = product(*options)
            
            for passwds in possibilities:
                passwords.append(''.join(passwds))
                
    return passwords


# Make sure I was given all the inputs that I need (and no more)
if (len(sys.argv) != 3):
    print("Invalid syntax")
    sys.exit(1)
    
# open the password file and read in the contents
fd = open(sys.argv[1], 'r', encoding='latin-1')
passes = fd.readlines()
fd.close()

# open the dictionary file and read in the contents
fd = open(sys.argv[2], 'r', encoding='latin-1')
words = fd.readlines()
fd.close()

# Calc the number of lines in each file
num_passes = len(passes)
num_words  = len(words)

# Output some stats
print("-----------------------------")
print("Pre-processing of input data:")
print("-----------------------------")
print("Number of passwords = " + str(num_passes))
print("Number of words     = " + str(num_words))

# Extract the hashes from the password file for quicker comparisons
print("Extracting hashes from file")
hashes = []      # an array of the hashes
for line in passes:
    # Find where the braces are
    index1 = line.find('{')
    index2 = line.find('}')
    if (index1 <= 0) or (index2 <= 0):
        print("bad password file format")
        sys.exit(1)
    if (index2 <= index1):
        print("bad password file format")
        sys.exit(1)

    # Extract the algorithm and make sure it is SHA
    if ((line[index1+1:index2]) != "SHA"):
        print("Error: only input SHA1-based hashes")
        sys.exit(1)

    # Extract the hash, remove the trailing carriage return, and do the
    # Base64 decoding.
    hashes.append(base64.b64decode(line[index2+1:].strip('\n')).hex())

# Now hash each word in the given dictionary and see if they match
# anything in the password file.
words_tried = 0
found = 0
print("-----------------------------")
print("Cracking...")
print("-----------------------------")
start_time = time()

found_users = set()  # Set to track users whose passwords we've cracked

for word in words:
    words_tried += 1
    for n in range(0, 3):
        for hash in haxor(word, n):
            newhash = hashlib.sha1(hash.strip('\n').encode()).hexdigest()
            index = 0
            while index < num_passes:
                if newhash == hashes[index]:
                    # Extract user name from password entry
                    name_index = passes[index].find(':')
                    name = passes[index][:name_index]

                    # Only count if the user hasn't been found before
                    if name not in found_users:
                        print(name + " password is '" + hash.strip('\n') + "'")
                        found_users.add(name)  # Add to set of found users
                        found += 1
                    
                index += 1
                
            # Stop early if we've found all the passwords
            if found >= num_passes:
                break


stop_time = time()
total_time = stop_time - start_time
            
# Display statistics at the end
print("-----------------------------")
print("Found " + str(found) + " out of " + str(num_passes) + " passwords.")
sys.stdout.write("Processed " + str(words_tried) + " words in ")
print(str(round(total_time,3)) + " seconds.")


