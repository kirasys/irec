import os
import sys
import json
import angr
import pprint
import logging
import datetime
import argparse
import boltons.timeutils

from projects import wdm

class FullPath(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, os.path.abspath(os.path.expanduser(values)))

def parse_is_file(dirname):
    if not os.path.isfile(dirname):
        msg = "{0} is not a file".format(dirname)
        raise argparse.ArgumentTypeError(msg)
    else:
        return dirname

def setupLogging(args):
    level = getattr(logging, args.log)
    logging.getLogger('angr').setLevel(level)

def parseArguments():
    parser = argparse.ArgumentParser(description='Automatic Driver Analysis', usage='driver.py [-d, --driver] driverPath [-L, --log] logLevel [-s, --skip] [-o, --output] output')
    parser.add_argument('-driver', metavar='<file>', required=True, action=FullPath,
                        type=parse_is_file, help='path to the driver')
    parser.add_argument('-log', default='FATAL', choices=('DEBUG', 'INFO', 'WARNING', 'ERROR', 'FATAL'), help='set a logging level')
    parser.add_argument('-skip', default=False, action='store_true', help='skip the functions that do not need to be analyzed')
    parser.add_argument('-output', metavar='<file>', action=FullPath, help='path to a output file')
    return parser, parser.parse_args()

if __name__ == '__main__':
    parser, args = parseArguments()
    setupLogging(args)

    if len(sys.argv) <= 1:
        print("usage: %s" % parser.usage)
        sys.exit()

    start_time = datetime.datetime.utcnow()
    driver = wdm.WDMDriverAnalysis(args.driver, skip_call_mode=args.skip)

    if driver.isWDM():
        print("Finding DeviceName...")
        device_name = driver.find_device_name()
        print("\t> DeviceName : %s\n" % device_name)

        print("Finding DispatchDeviceControl...")
        mj_device_control_func = driver.find_dispatcher()
        print("\t> DispatchDeviceControl : 0x%x\n" % mj_device_control_func)

        print("Recovering the IOCTL interface...")
        ioctl_interface = driver.recovery_ioctl_interface()
        print("\t> IOCTL Interface :")
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(ioctl_interface)

        elapsed = boltons.timeutils.decimal_relative_time(start_time, datetime.datetime.utcnow())
        print("\nCompleted ({0:.1f} {1})".format(*elapsed))

        if args.output:
            with open(args.output, "w") as json_file:
                json.dump(ioctl_interface, json_file)
    else:
        print("[!] '%s' is not a supported driver." % args.driver)
        sys.exit()
