import sys
import re

def encapsulateDocsting(comment):
    ret = '"""' + "\n"
    ret += comment
    ret += '"""'
    return ret

def cleanupJavaComment(comment):
    lines = comment.split("\n")
    
    ret = ""
    for line in lines:
        line = line.strip()
        if line[:2] == "* ":
            line = line[2:]
        elif line[:1] == "*":
            line = line[1:]
        ret += line + "\n"
        
    return ret[:-1] #Drop the last newline
    
##########################3

INPUTFILE = sys.argv[1]

f = open(INPUTFILE, 'r')
lines = f.readlines()
f.close()

# Get into one string
lines = "".join(lines)

m = re.compile('\/\*\*?[\r\n]?(.*?)\*\/', re.DOTALL)

rawComments = m.findall(lines)
cleanComments = [cleanupJavaComment(c) for c in rawComments]

for cleanComment in cleanComments:
    print "\n",encapsulateDocsting(cleanComment)
