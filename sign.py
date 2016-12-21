# Version 2
import angr, pyvex, argparse
from block import entry_addr, set_successors, get_successors, ret_successors

regs_offset = {}
blocks = {}
tmps = {}
tmps_const = {}
initial_sp = 0x00000000
p = None

class Sign_CFG_Block(object):
    def __init__(self, addr):
        self.addr = addr
        self.regs = {}
        self.regs_const = {}
        self.tmp_regs = {}
        self.tmp_regs_const = {}
        for reg in p.arch.default_symbolic_registers:
            self.regs[reg] = []
        self.regs['eip'] = [1]
        self.regs['esp'] = [1]
        self.regs['ebp'] = [1]

        self.mem = {}   #keep track of stack variables here
        self.mem_const = {}

        #self.tmp_regs = {}
    def is_subset_of(self, other):
        if self.addr != other.addr or len(self.regs) != len(other.regs) or len(self.tmp_regs) != len(other.tmp_regs):
            return ValueError("Critical error: comparing imcompatible SignStates")

        for reg in self.regs:
            if not self.regs[reg].is_subset_of(other.regs[reg]):
                return False

        for tmp_reg in self.tmp_regs:
            if not self.tmp_regs[tmp_reg].is_subset_of(other.tmp_regs[tmp_reg]):
                return False

        return True

    def union(self, other): # This Unions currently makes little sense
        #traceback.print_stack
        if self.addr != other.addr or len(self.regs) != len(other.regs) or len(self.tmp_regs) != len(other.tmp_regs):
            return ValueError("Critical error: comparing imcompatible SignStates")

        out = SignState(self.addr)

        for reg in self.regs:
            out.regs[reg] = self.regs[reg].union(other.regs[reg])

        for tmp_reg in self.tmp_regs:
            out.tmp_regs[tmp_reg] = self.tmp_regs[tmp_reg].union(other.tmp_regs[tmp_reg])

        for m in self.mem:
            out.mem[m] = self.mem[m].union(other.mem[m])
        print out
        raw_input()
        return out

    def save_tmp_status(self, tmps, tmps_const):
        self.tmp_regs = tmps
        self.tmp_regs_const = tmps_const

    def pp2(self):
        return {'mem': self.mem, 'regs': self.regs}

    def pp(self):
        print "Block Address: " ,hex(self.addr)
        print "Register Sign:"
        for reg_key  in self.regs: print reg_key, ":" , self.regs[reg_key]
        for reg_const_key  in self.regs_const:print reg_const_key, ":" , hex(self.regs_const[reg_const_key])
        print "Memory Sign:"
        for mem_key  in self.mem: print hex(mem_key), ":" , self.mem[mem_key]
        for mem_const_key  in self.mem_const: print hex(mem_const_key), ":" , hex(self.mem_const[mem_const_key])
        print "--------------------------------------------------"

def handle_tmp_assignment(lfs, rhs):
	global regs_offset, blocks, tmps, tmps_const, initial_sp
	handle_flag = 0
	if rhs in tmps:
		tmps[lfs] = tmps[rhs]
		handle_flag = 1
	if rhs in tmps_const:
		tmps_const[lfs] = tmps_const[rhs]
		handle_flag = 1
	if handle_flag != 1: print '\tUnhandled (tmp =): missing RHS value'

def handle_add_tmp_const(lfs, rhs, const_value):
	global regs_offset, blocks, tmps, tmps_const, initial_sp
	handle_flag = 0
	if rhs in tmps:
		if tmps[rhs] == [1]:
			if const_value > 0:
				tmps[lfs] = [1]
				handle_flag = 1
	if rhs in tmps_const:
		res_value = tmps_const[rhs] + const_value
		tmps_const[lfs] = res_value
		if res_value > 0: tmps[lfs] = [1]
		elif res_value == 0: tmps[lfs] = [0]
		else: tmps[lfs] =  [2]
		handle_flag = 1
	if handle_flag != 1: print "\tUnhandled (add tmp): RHS unknown"

def handle_sub_tmp_const(lfs, rhs, const_value):
	global regs_offset, blocks, tmps, tmps_const, initial_sp
	handle_flag = 0
	if rhs in tmps:
		if tmps[rhs] == [2]:
			if const_value < 0:
				tmps[lfs] = [2]
				handle_flag = 1
	if rhs in tmps_const:
		res_value = tmps_const[rhs] - const_value
		tmps_const[lfs] = res_value
		if res_value > 0: tmps[lfs] = [1]
		elif res_value == 0: tmps[lfs] = [0]
		else: tmps[lfs] =  [2]
		handle_flag = 1
	if handle_flag != 1: print "\tUnhandled (sub tmp): RHS unknown"

def handle_and_tmp_const(lfs, rhs, const_value):
	global regs_offset, blocks, tmps, tmps_const, initial_sp
	handle_flag = 0
	if rhs in tmps_const:
		res_value = tmps_const[rhs] & const_value
		tmps_const[lfs] = res_value
		if res_value > 0: tmps[lfs] = [1]
		elif res_value == 0: tmps[lfs] = [0]
		else: tmps[lfs] =  [2]
		handle_flag = 1
	if handle_flag != 1: print "\tUnhandled (sub tmp): RHS unknown"

def handle_store(addr, value, sblock):
	global regs_offset, blocks, tmps, tmps_const, initial_sp
	if value > 0x7FFFFFFF: value = -(0x7FFFFFFF - value + 1)
	#print hex(addr)
	#break

	sblock.mem[addr] = value
	if value > 0: sblock.mem[addr] = [1]
	elif value == 0: sblock.mem[addr] = [0]
	else: sblock.mem[addr] = [2]

def traverse(node):
	global regs_offset, blocks, tmps, tmps_const, initial_sp
	test_sign_block = Sign_CFG_Block(node.addr)
	irsb = node.irsb
	if irsb == None: pass

	for stmt_idx, stmt in enumerate(irsb.statements):
		if type(stmt) is pyvex.IRStmt.IMark: continue
		if type(stmt) is pyvex.stmt.Exit: break
		elif type(stmt) is pyvex.IRStmt.Store:
			addr = stmt.addr
			data = stmt.data
			if  isinstance(addr, pyvex.IRExpr.RdTmp) and addr.tmp in tmps_const:
				addr_val = tmps_const[addr.tmp]
				if isinstance(data, pyvex.IRExpr.Const):
					stored_value = data.con.value
					handle_store(addr_val, stored_value, test_sign_block)
					#break
				elif isinstance(data, pyvex.IRExpr.RdTmp):
					data_tmp_num = data.tmp
					if data_tmp_num in tmps_const:
						stored_value = tmps_const[data_tmp_num]
						handle_store(addr_val, stored_value, test_sign_block)
						#break
					else: print "\tUnhandled (Store): Unknown RHS", stmt_idx, stmt
			else: print "\tUnhandled (Store)",stmt_idx, stmt
		elif type(stmt) is pyvex.IRStmt.WrTmp:
			data = stmt.data
			if type(data) is pyvex.IRExpr.Get:
				tmp_num = stmt.tmp
				reg_name = regs_offset[stmt.data.offset]
				tmps[tmp_num] = test_sign_block.regs[reg_name]
				if reg_name == 'esp': tmps_const[tmp_num] = initial_sp # RAISES INDEX ERROR
			elif type(data) is pyvex.IRExpr.Load:
				load_to_tmp_num = stmt.tmp
				addr = stmt.data.addr
				if isinstance(addr, pyvex.IRExpr.RdTmp):
					load_from_tmp_num = addr.tmp
					if load_from_tmp_num in tmps_const and tmps_const[load_from_tmp_num] in test_sign_block.mem:
						tmps[load_to_tmp_num] = test_sign_block.mem[tmps_const[load_from_tmp_num]]
						if load_from_tmp_num in test_sign_block.mem_const:
							tmps_const[load_to_tmp_num] = test_sign_block.mem_const[load_from_tmp_num]
					else: print '\tUnhandle (Load) Instance Combo:', stmt_idx, stmt
				else: print '\tUnhandled (Load)', stmt_idx, stmt
			elif type(data) is pyvex.IRExpr.Unop:
				write_to_tmp_num = stmt.tmp
				arg0 = data.args[0]
				if isinstance(arg0, pyvex.IRExpr.RdTmp): handle_tmp_assignment(write_to_tmp_num,arg0.tmp)
				else: print "\tUnhandled (Unop)", stmt_idx, stmt
			elif type(data) is pyvex.IRExpr.Binop:
				arg0, arg1 = data.args
				if data.op == 'Iop_Add32':
					if isinstance(arg0, pyvex.IRExpr.RdTmp) and isinstance(arg1, pyvex.IRExpr.Const):
						added_value = arg1.con.value
						if added_value < 0x7FFFFFFF: pass
						else: added_value = -(0xffffffff - added_value + 1)
						handle_add_tmp_const(stmt.tmp ,arg0.tmp, added_value)
					else: print  '\tUnhandled (Iop_Add32)', stmt_idx, stmt
				elif data.op == 'Iop_Sub32':
					if isinstance(arg0, pyvex.IRExpr.RdTmp) and isinstance(arg1, pyvex.IRExpr.Const):
						sub_value = arg1.con.value
						if sub_value < 0x7FFFFFFF: pass
						else: sub_value = -(0x7FFFFFFF - sub_value + 1)
						handle_sub_tmp_const(stmt.tmp, arg0.tmp, sub_value)
					else: print '\tUnhandled (Iop_Sub32)', stmt_idx, stmt
				elif data.op == 'Iop_And32':
					if isinstance(arg0, pyvex.IRExpr.RdTmp) and isinstance(arg1, pyvex.IRExpr.Const):
						handle_and_tmp_const(stmt.tmp ,arg0.tmp, arg1.con.value)
					else: print '\tUnhandled (Iop_And32):', stmt_idx, stmt
				elif data.op in ('Iop_Div32','Iop_Div64', 'Iop_DivModS64to32'):
					if isinstance(arg1, pyvex.IRExpr.Const):
						if arg1.con.value == 0: print 'DIVISION BY 0', stmt_idx, stmt, ' at block ', hex(node.addr)
					elif isinstance(arg1, pyvex.IRExpr.RdTmp):
						if tmps_const[arg1.tmp] == 0: print 'DIVISION BY 0', stmt_idx, stmt, ' at block ', hex(node.addr)
					else: '\tUnhandled (Division) Args:', stmt_idx, stmt
			elif type(data) is pyvex.IRExpr.RdTmp: handle_tmp_assignment(stmt.tmp,data.tmp)
			else: '\tUnhandle (WrTmp)', stmt_idx, stmt
		elif type(stmt) is pyvex.IRStmt.Put:
			if stmt.offset in regs_offset:
				data = stmt.data
				reg_name = regs_offset[stmt.offset]
				if isinstance(data, pyvex.IRExpr.RdTmp):
					tmp_num = data.tmp
					if tmp_num in tmps: test_sign_block.regs[reg_name] = tmps[tmp_num]
					if tmp_num in tmps_const: test_sign_block.regs_const[reg_name] = tmps_const[tmp_num]
				elif isinstance(data, pyvex.IRExpr.Const):
					constant = data.con.value
					if constant > 0x7FFFFFFF: test_sign_block.regs[reg_name] = [2]
					elif constant == 0: test_sign_block.regs[reg_name] = [0]
					else: test_sign_block.regs[reg_name] = [1]
		else: print '\tUnhandled (IRSB Statement)', stmt_idx, stmt

		test_sign_block.save_tmp_status(tmps, tmps_const)

	blocks[test_sign_block.addr] = test_sign_block
	test_sign_block.pp()

	# Experimental: Finding sucessors and storing them (block.py)
	for s_idx in range(0, len(node.successors)): set_successors(node.addr, node.successors[s_idx])

def main():
	global regs_offset, blocks, tmps, tmps_const, initial_sp, p
	parser = argparse.ArgumentParser()
	parser.add_argument("-b", "--binary", help = "Desired binary path to analyze", required = True)
	parser.add_argument("-f", "--function", help = "Desired function to analyze", required = False)
	args = parser.parse_args()

	binary = args.binary
	function = 'main'
	if args.function: function = args.function

	# Inputting project binary
	p = angr.Project(binary)

	# Getting all registers for binary and storing them
	regs_offset = {}
	for reg in p.arch.default_symbolic_registers:
		regs_offset[p.arch.registers[reg][0]] = reg
	if 'eip' in p.arch.registers: regs_offset[p.arch.registers['eip'][0]] = 'eip'
	
	# Find the address of the function to perform analysis on
	#initial_sp = entry_addr(binary, function)
	func_to_analysis_addr = entry_addr(binary, function)
	initial_sp = 0x7fff0000

	cfg = p.analyses.CFGAccurate(keep_state = True, context_sensitivity_level = 0)
	main_cfg = cfg.get_function_subgraph(func_to_analysis_addr)

	main_nodes = main_cfg.graph.node
	cfg_nodes = main_nodes.keys()

	# Sort cfg_nodes by address
	addrs = []
	cfg_nodes_map = {}
	for node in cfg_nodes:
		addrs.append(node.addr)
		cfg_nodes_map[node.addr] = node
	addrs = sorted(addrs)
	cfg_nodes = []
	for addr in addrs: cfg_nodes.append(cfg_nodes_map[addr])

	# PERFORM SIGN ANALYSIS
	print cfg_nodes
	for node in cfg_nodes:
		try: traverse(node)
		except Exception as e: print '\t', e

	# Output sucessors
	print '\nSuccessors:'
	successors = ret_successors()

	for s in sorted(successors.keys()):
		if s in addrs:
			print str(hex(s)) + ':',
			for successor in successors[s]: print hex(successor.addr),
			print ''

main()