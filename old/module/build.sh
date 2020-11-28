#!/bin/bash

rmmod proc_module
make
insmod proc_module.ko
