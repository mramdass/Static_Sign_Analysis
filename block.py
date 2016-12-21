from subprocess import Popen, PIPE

def entry_addr(executable, function = 'main'):

	p = Popen(['objdump', '-d', 'test'], stdin=PIPE, stdout=PIPE, stderr=PIPE)
	output, err = p.communicate(b"input data that is passed to subprocess' stdin")
	rc = p.returncode

	output = output.split()
	for seg in range(len(output)):
		if output[seg] == '<' + function + '>:': return int(output[seg - 1], 16)
	return 0x00000000

#___________________________________________________
# Experimental: Finding sucessors and storing them
successors = {}
def set_successors(k, v):
	if k not in successors:
		successors[k] = []
		successors[k].append(v)
	else: successors[k].append(v)

def ret_successors(): return successors

def get_successors(k): return successors[k]
#___________________________________________________