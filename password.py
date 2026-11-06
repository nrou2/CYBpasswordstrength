#Intro to Cyber Group Project
#Password Strength Checker
#Authors: Nathan Rouse, John Gawlinski

import sys
import math
import json



#Establishing the base calculating function for mostly random sets
def calculate(tokenlength,attempts):
    unit = "seconds"


    seconds = attempts / rate
    minutes = seconds / 60
    hours = minutes / 60
    days = hours / 24
    weeks = days / 7
    years = days / 365

    if years >= 1:
        time = years
        unit = "years"
    elif weeks >= 1:
        time = weeks
        unit = "weeks"
    elif days >= 1:
        time = days
        unit = "days"
    elif hours >= 1:
        time = hours
        unit = "hours"
    elif minutes >= 1:
        time = minutes
        unit = "minutes"
    else:
        time = seconds
        unit = "seconds"
    return time, unit
#Take initial input
print("Enter the password you wish to test.")
password = input()
print("Enter how many attempts you are expecting your password to be brute forced per second.")
print("Rate limited interfaces can expect single digits, offline attacks can expect ~200 billion on the highest end gpus such as a 5090.")
print("You can use 1 billion (1000000000) (10 digits, 9 zeroes) as a default.")
rate = int(input())
#Parse through the list of 100k most common passwords
with open("common.txt", "r", encoding="utf-8") as file:
    lines = [line.rstrip("\n") for line in file]
#Open the dictionary file to look for immediate dictionary words
with open("words_dictionary.json", "r") as file:
    words = json.load(file)

#But a dictionary alone doesn't tell the full story, a word like "the" doesn't have the same 1/370k chance as others
#For this, we have a second dictionary, much smaller, 25k instead of 400k, but providing frequency data
with open("wordfreq-en-25000-log.json", "r") as file:
    wordsfreq = json.load(file)
    
wordrank = {}
for i, entry in enumerate(wordsfreq):
    wordrank[entry[0]] = i + 1

#Before calculating, it's best to see if the given password matches a common one.
#Brute force attacks will likely go straight for these before random probability and time becomes a factor.
if password in lines:
    print("Your password was found in the 100,000 most common passwords. It would not be brute forced, it would be directly attempted immediately.")
    sys.exit()
    

#From here, we should gather a bit of information on the password. Passwords using just letters are going to be much easier cracked.
#Passwords using letters and numbers are going to be better, but not there.
#When symbols enter, things become much less predictable and closer to raw random permutations of the character list.
justletters = password.isalpha()
justnumbers = password.isdigit()
hassymbols  = password.isalnum()
wordcount = 0
wordlist = []
newpassword = password
#The following variable is the compression of words into their frequency
#such that something like "the" represents being a top ten token in a dictionary attack,
#rather than something like 96^3 from its raw characters.
#Wasn't sure how to give it a descriptive yet still reasonably short name.
dictionaries = 0
wordfound = False
if hassymbols == True:
    hassymbols = False
else:
    hassymbols = True

if not justnumbers:
    for word in wordsfreq:
        #I and A can be treated as false positives, since even truly random letters would trigger this dictionary detection.
        #Hence, we try to only count entries that are at least above a single letter. It's possible that some words like am appear in a truly random string.
        #But false detection should not affect their strength by a meaningful amount if they are already strong passwords.
        if word[0] in newpassword and len(word[0]) > 1:
            wordcount+=1
            wordlist.append(word[0])
            wordfound = True
            newpassword = newpassword.replace(word[0], "")
            dictionaries+= wordrank[word[0]]

    #Here we will replace entries that are not found in the frequency dictionary, but still found in the basic dictionary with 210k
    #Approximately half the list length +25k due to us having already scanned through the most common 25k words, as an estimate
    #We will only do this for words >2 characters, as elsewise their char by char brute force value is cheaper than this value.
    for word in words:
        if word in newpassword and len(word[0]) > 2:
            wordcount+=1
            wordlist.append(word)
            wordfound = True
            newpassword = newpassword.replace(word[0], "")
            dictionaries+= 210000
        


            
        

if hassymbols:
    #Later on, there should be more detailed checks to see if the password appears close to dictionary words.
    #For the early stages of the program, I am simply assuming symbols = assume purely random
    random = True

    if random:
        length = len(newpassword)
        #96 total symbols for the upper and lower alphabet, numbers, and remaining ascii symbols. Assuming no unicode.
        attempts = 96**length + dictionaries
        time, unit = calculate(length,attempts)

        
        print("Your password appears mostly random. Considering that, it would take an estimated " + str(time) + " " + unit + " to brute force.")
elif justnumbers: 
    print("Your password being just numbers gives an easier set to predict, be advised.")
    length = len(password)
    attempts = 10**length
    time,unit = calculate(length,attempts)
    print("Your password has only 10 possible characters. Considering that, it would take an estimated " + str(time) + " " + unit + " to brute force.")
    print("Be aware that important dates like birthdates will be guessed first as soon as anybody finds them.")
elif justletters:
    print("Your password being just letters gives an easier set to predict, be advised.")
    length = len(newpassword)
    attempts = 52**length + dictionaries
    time,unit = calculate(length,attempts)
    print("Your password has only 52 possible characters. Considering that, it would take an estimated " + str(time) + " " + unit + " to brute force.")
    


else:
    print("Your password contains letters and numbers. It would be better with symbols, but it isn't the worst.")
    length = len(password)
    attempts = 62**length
    time,unit = calculate(length,attempts)
    print("Your password has 62 possible characters. Considering that, it would take an estimated " + str(time) + " " + unit + " to brute force.")
    
if wordfound:
    print("The following substantial dictionary words were found in your password, which drastically reduced the strength.")
    print(wordlist)
    print("Were no reductions taken, the result would have been:")
    length = len(password)
    attempts = 96**length
    time,unit = calculate(length,attempts)
    print("Your password appears mostly random. Considering that, it would take an estimated " + str(time) + " " + unit + " to brute force.")
