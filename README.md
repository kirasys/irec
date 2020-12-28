# What is MadCore?
A cross platform framework to recover driver's communication interface. It aims to recover communication interface for fuzzing a kernel driver.

## Project structure
```text
IREC
├── test-drivers                          # Test drivers to verify that madcore is working.
├── projects                              # Driver analysis projects
│   ├── symbolic                          # Techniques using symbolic execution.
│   ├── static                            # Techniques using static analysis techniques
│   └──wdm.py                             # WDM driver analysis framework
└── irec.py                               # Main module
```

## Requirements
~~~{.sh}
# install dependencies
$ pip install angr boltons argparse ipdb
~~~
