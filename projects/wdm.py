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
        #kwargs['use_sim_procedures'] = kwargs.pop('use_sim_procedures', False)
        
        self.driver_path = args[0]
        # Static binary analysis using radare2
        self.func_analyzer = FunctionAnalysis(self.driver_path)

        self.skip_call_mode = kwargs.pop('skip_call_mode', False)
        if self.skip_call_mode:
            kwargs['support_selfmodifying_code'] = True

        super(WDMDriverAnalysis, self).__init__(*args, **kwargs)
        self.factory = WDMDriverFactory(self)
        self.project = self.factory.project

        self.DispatchCreate = 0
        self.DispatchDeviceControl = 0

        self.ioctl_constraints = []
        self.datas = []
    
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
            self.use_skip_call_mode(state, [arg_driverobject])

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
    
    def skip_function_by_arguments(self, state):
        """
        Don’t use this function manually - Breakpoint event handler used in use_skip_call_technique.
        """

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

                for arg in self.allowed_arguments:
                    if isinstance(arg, str) and arg in argument:
                        skip = False
            else:
                argument = state.solver.eval(argument)

                if argument in self.allowed_arguments:
                    skip = False

            if skip == False:
                break

        if skip:
            state.mem[state.regs.rip].uint8_t = 0xc3
            state.regs.rax = state.solver.BVS('ret', 64)

    def use_skip_call_mode(self, state, arguments):
        """
        :state:         Target state to apply skip call mode
        :arguments:     
        """

        self.allowed_arguments = arguments

        state.inspect.b('call', action=self.skip_function_by_arguments)

    def recovery_ioctl_interface(self):
        """
        Returns IOCTL interface of the given driver.

        - IOCTL Interface
        :code:          IoControlCode
        :constraints:   constraints of InputBufferLength, OutputBufferLength
        """

        state = self.project.factory.call_state(self.DispatchDeviceControl, arg_driverobject, arg_irp)
        
        # for medcored.sys (should be removed.)
        #setattr(state.mem[0x10C5B8], 'uint64_t', state.solver.BVS('x', 64))

        if self.skip_call_mode:
            self.use_skip_call_mode(state, [arg_iostacklocation, 'IoControlCode', 'SystemBuffer', 'CurrentStackLocation'])

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
        for ioctl_code, switchstate in switch_states.items():
            tmpstate = switchstate.copy()
            tmpstate.solver.add(irp.fields['AssociatedIrp.SystemBuffer'] == 0)
            tmpstate.solver.add(io_stack_location.fields['InputBufferLength'] == 0xffffffff)
            tmpstate.solver.add(io_stack_location.fields['OutputBufferLength'] == 0xffffffff)
    
            def get_else_state(st):
                simgr = self.project.factory.simgr(st)

                for i in range(10):
                    simgr.step()

                    for states in list(simgr.stashes.values()):
                        for state in states:
                            for constraint in state.history.jump_guards:
                                if 'Buffer' in str(constraint):
                                    return state

            elsestate = get_else_state(tmpstate)

            def get_if_state(st, elsestate):
                simgr = self.project.factory.simgr(st)

                for i in range(10):
                    simgr.step()

                for states in list(simgr.stashes.values()):
                    for state in states:
                        if elsestate.addr not in state.history.bbl_addrs:
                            return state

            constraints = []
            if elsestate:
                ifstate = get_if_state(switchstate, elsestate)
                for constraint in ifstate.history.jump_guards:
                    if 'Buffer' in str(constraint):
                        constraints.append(constraint)

            ioctl_interface.append({'code': hex(ioctl_code), 'constraints': constraints})
        
        return ioctl_interface