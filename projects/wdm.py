import re
import sys
import angr
import claripy
import archinfo
from pprint import pprint as pp

from .symbolic import explore_technique
from .symbolic import structures
from .static.static_analysis import FunctionAnalysis

DispatchDeviceControl_OFFSET = 0xe0
DispatchCreate_OFFSET = 0x70

arg_deviceobject = 0xdead0000
arg_driverobject = 0xdead1000
arg_registrypath = 0xdead2000

arg_irp = 0xdead3000
arg_iostacklocation = 0xdead4000

import ipdb

def ast_repr(node):
    if not isinstance(node, claripy.ast.Base):
        raise TypeError('node must be an instance of claripy.ast.Base not: ' + repr(node))
    return re.sub(r'([^a-zA-Z][a-zA-Z]+)_\d+_\d+([^\d]|$)', r'\1\2', node.__repr__(inner=True))

class WDMDriverFactory(angr.factory.AngrObjectFactory):
    """
    This class provides state presets of window.
    """

    def __init__(self, *args, **kwargs):
        super(WDMDriverFactory, self).__init__(*args, **kwargs)

        # set the default calling convention
        if isinstance(self.project.arch, archinfo.ArchAMD64):
            self._default_cc = angr.calling_conventions.SimCCMicrosoftAMD64(self.project.arch)
        else:
            raise ValueError('Unsupported architecture')

    def call_state(self, addr, *args, **kwargs):
        # Todo : little endian and big endian confliction.
        #kwargs['add_options'] = kwargs.pop('add_options', angr.options.unicorn)
        cc = kwargs.pop('cc', self._default_cc)
        kwargs['cc'] = cc

        return super(WDMDriverFactory, self).call_state(addr, *args, **kwargs)

class WDMDriverAnalysis(angr.Project):
    """
    This class provides functions which analyze WDM driver.
    """

    def __init__(self, *args, **kwargs):
        """
        - kwargs
        :skip_call_mode: Allow only certain functions by its arguments
        """

        kwargs['auto_load_libs'] = kwargs.pop('auto_load_libs', False)
        kwargs['support_selfmodifying_code'] = True
        #kwargs['use_sim_procedures'] = kwargs.pop('use_sim_procedures', False)
        
        self.driver_path = args[0]
        # Static binary analysis using radare2
        self.func_analyzer = FunctionAnalysis(self.driver_path)
        self.skip_call_mode = kwargs.pop('skip_call_mode', False)

        super(WDMDriverAnalysis, self).__init__(*args, **kwargs)
        self.factory = WDMDriverFactory(self)
        self.project = self.factory.project

        self.DispatchCreate = 0
        self.DispatchDeviceControl = 0

        self.mode = {}
        self.global_variables = []

    def isWDM(self):
        """
        Returns True if the given binary is WDM driver. 
        """

        return True if self.project.loader.find_symbol('IoCreateDevice') else False

    def find_device_name(self):
        """
        Returns DeviceName of the given driver. It searchs "DosDevices" statically.
        """

        DOS_DEVICES = "\\DosDevices\\".encode('utf-16le')
        data = open(self.driver_path, 'rb').read()

        cursor = data.find(DOS_DEVICES)
        terminate = data.find(b'\x00\x00', cursor)

        if ( terminate - cursor) %2:
            terminate +=1
        match = data[cursor:terminate].decode('utf-16le')
        return match

    def set_major_functions(self, state):
        """
        Don’t use this function manually - Breakpoint event handler used in find_DispatchDeviceControl.
        """

        self.DispatchCreate = state.mem[arg_driverobject + DispatchCreate_OFFSET].uint64_t.concrete
        self.DispatchDeviceControl = state.solver.eval(state.inspect.mem_write_expr)

    def find_DispatchDeviceControl(self):
        """
        Returns address of DispatchDeviceControl function.

        Set a breakpoint on DriverObject->MajorFunctions[MJ_DEVICE_CONTROL]
        """

        state = self.project.factory.call_state(self.project.entry, arg_driverobject, arg_registrypath)
        if self.skip_call_mode:
            self.set_mode('skip_call', state, allowed_arguments=[arg_driverobject])

        simgr = self.project.factory.simgr(state)

        # Set a breakpoint on DriverObject->MajorFuntion[MJ_DEVICE_CONTROL]
        state.inspect.b('mem_write',when=angr.BP_AFTER,
                        mem_write_address=arg_driverobject+DispatchDeviceControl_OFFSET,
                        action=self.set_major_functions)

        # DFS exploration
        simgr.use_technique(angr.exploration_techniques.dfs.DFS())
        simgr.run(until=lambda x: self.DispatchDeviceControl)

        # Second exploration
        # to skip default mj function initialization.
        if self.DispatchDeviceControl == self.DispatchCreate:
            for i in range(50):
                simgr.step()

                if self.DispatchDeviceControl != self.DispatchCreate:
                    break

        return self.DispatchDeviceControl

    def set_mode(self, mode, state, off=False, allowed_arguments=[]):
        """
        Set a mode.

        - mode
        :force_skip_call:   Force any functon to return.
        :skip_call:         Skip certain functions according to arguments it use.
        """

        if mode == 'force_skip_call':
            if not off:
                def force_skip_call(state):
                    state.mem[state.regs.rip].uint8_t = 0xc3
                    state.regs.rax = state.solver.BVS('ret', 64)

                self.mode[mode] = state.inspect.b('call', action=force_skip_call)
            else:
                state.inspect.remove_breakpoint('call', self.mode[mode])

        elif mode == 'skip_call':
            if not off:
                def skip_function_by_arguments(state):
                    # Analyze prototype of the current function.
                    func_prototypes = self.func_analyzer.prototype(state.addr)

                    skip = True
                    for arg_type in func_prototypes:
                        if '+' not in arg_type:     # register
                            argument = getattr(state.regs, arg_type)
                        else:                       # stack value
                            offset = int(arg_type.split('+')[-1], 16)
                            argument = state.mem[getattr(state.regs, arg_type.split('+')[0]) + offset].uint64_t.resolved
                            
                        if argument.symbolic:
                            argument = str(argument)

                            for arg in allowed_arguments:
                                if isinstance(arg, str) and arg in argument:
                                    skip = False
                        else:
                            argument = state.solver.eval(argument)

                            if argument in allowed_arguments:
                                skip = False

                        if skip == False:
                            break

                    if skip:
                        state.mem[state.regs.rip].uint8_t = 0xc3
                        state.regs.rax = state.solver.BVS('ret', 64)

                self.mode[mode] = state.inspect.b('call', action=skip_function_by_arguments)
            else:
                state.inspect.remove_breakpoint('call', self.mode[mode])

        elif mode == 'symbolize_global_variables':
            self.global_variables = []

            if not off:
                def symbolize_global_variables(state):
                    obj = self.project.loader.main_object
                    mem_read_address = state.solver.eval(state.inspect.mem_read_address)
                    section = obj.find_section_containing(mem_read_address)

                    if mem_read_address not in self.global_variables and '.data' in str(section):
                        self.global_variables.append(mem_read_address)
                        setattr(state.mem[mem_read_address], 'uint64_t', state.solver.BVS('global_%x' % mem_read_address, 64))

                self.mode[mode] = state.inspect.b('mem_read', condition=symbolize_global_variables)
            else:
                state.inspect.remove_breakpoint('mem_read', self.mode[mode])


    def recovery_ioctl_interface(self):
        """
        Returns IOCTL interface of the given driver.

        - IOCTL Interface
        :code:          IoControlCode
        :constraints:   constraints of InputBufferLength, OutputBufferLength
        """

        state = self.project.factory.call_state(self.DispatchDeviceControl, arg_driverobject, arg_irp)
        
        if self.skip_call_mode:
            self.set_mode('skip_call', state, allowed_arguments=[arg_iostacklocation, 'IoControlCode', 'SystemBuffer', 'CurrentStackLocation'])

        simgr = self.project.factory.simgr(state)

        io_stack_location = structures.IO_STACK_LOCATION(state, arg_iostacklocation)
        irp = structures.IRP(state, arg_irp)

        state.solver.add(irp.fields['Tail.Overlay.CurrentStackLocation'] == io_stack_location.address)
        state.solver.add(irp.fields['IoStatus.Status'] == 0)
        state.solver.add(io_stack_location.fields['MajorFunction'] == 14)

        state_finder = explore_technique.SwitchStateFinder(io_stack_location.fields['IoControlCode'])
        simgr.use_technique(state_finder)
        simgr.run()

        ioctl_interface = []
        switch_states = state_finder.get_states()
        for ioctl_code, case_state in switch_states.items():
            def get_constraint_states(st):
                self.set_mode('symbolize_global_variables', st)
                simgr = self.project.factory.simgr(st)

                for i in range(10):
                    simgr.step()

                    for state in simgr.active:
                        for constraint in state.history.jump_guards:
                            if 'Buffer' in str(constraint):
                                yield state

            constraint_states = get_constraint_states(case_state)

            try:
                sat_state = next(constraint_states)
                unsat_state = next(constraint_states)
            except:
                ioctl_interface.append({'code': hex(ioctl_code), 'constraints': []})
                continue

            self.set_mode('force_skip_call', unsat_state)
            simgr = self.project.factory.simgr(unsat_state)
            simgr.run(n=20)

            for state in simgr.deadended:
                if (state.solver.eval(state.regs.rax) >> 24) != 0xc0:
                    sat_state, unsat_state = unsat_state, sat_state
                    break

            def get_satisfied_state(sat_state, unsat_state):
                self.set_mode('symbolize_global_variables', sat_state)
                simgr = self.project.factory.simgr(sat_state)

                for i in range(10):
                    simgr.step()

                for states in list(simgr.stashes.values()):
                    for state in states:
                        if unsat_state.addr not in state.history.bbl_addrs:
                            return state

            constraints = []
            sat_state = get_satisfied_state(sat_state, unsat_state)
            for constraint in sat_state.history.jump_guards:
                if 'Buffer' in str(constraint):
                    constraints.append(constraint)
                if 'global_' in str(constraint):
                    constraints.append(constraint)

            ioctl_interface.append({'code': hex(ioctl_code), 'constraints': constraints})
        
        return ioctl_interface