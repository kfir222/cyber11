import sys


def read_file_content_to_dictionary(file_path):
    with open(file_path) as file:
        d = {}  
        for line in file:
            splited = line.split()       
            for word in splited:           
                if word in d:
                    d[word] += 1
                else:
                    d[word] = 1 
        return d
    

def sort_words_by_frequency(words_dict, n):
    l = sorted(words_dict.items(), key=lambda item: item[1], reverse=True)
    l = l[:n] # Keep only top N words
    sorted_dict = dict(l)
    return sorted_dict



if __name__ == "__main__":
    if len(sys.argv) > 1:
        n = int(sys.argv[1])
    else:
        raise Exception("Please enter N as sys argument")


    file_path = "C://Users//USER//Desktop//cyber11//hello.py"
    d = read_file_content_to_dictionary(file_path)
    d = sort_words_by_frequency(d, n)
    for key, value in d.items():
        print("Word: " + key + " Appears " + str(value) + " times")