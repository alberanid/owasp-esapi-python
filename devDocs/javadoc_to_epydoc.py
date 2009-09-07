import re
import sys

filename_input = sys.argv[1]
filename_output = sys.argv[2]

fin = open(filename_input, 'r')
text = fin.read()
fin.close()

######## Apply changes

# Remove <p>
p = re.compile('<p>', re.IGNORECASE)
text = re.sub(p, '', text)

# Remove <br>
p = re.compile('<br>', re.IGNORECASE)
text = re.sub(p, '', text)

# Images
p = re.compile(r'<a href="(.*?)">[ \r\n]*(.*?)[ \r\n]*</a>', re.DOTALL)
text = re.sub(p, r'U{\2<\1>}', text)

# Throws -> raises
p = re.compile('throws', re.IGNORECASE)
text = re.sub(p, 'raises', text)

# Parameterized tags
p = re.compile(r'^( *@(param|raises)) (\w+)[ \r\n]*(.*?)$', re.DOTALL | re.MULTILINE)
text = p.sub(r'\1 \3: \4', text)

# Other tags
p = re.compile(r'^( *@(see|return|author))[ \r\n]*(.*?)$', re.DOTALL | re.MULTILINE)
text = p.sub(r'\1: \3', text)

# Li -> indented list
p = re.compile('<li>', re.IGNORECASE)
text = re.sub(p, '    - ', text)

p = re.compile('</li>', re.IGNORECASE)
text = re.sub(p, '', text)

# Write it out
fout = open(filename_output, 'w')
fout.write(text)
fout.close()