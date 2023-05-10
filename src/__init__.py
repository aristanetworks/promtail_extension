# ------------------------------------------------------------------------------
#  Copyright (c) 2021-2023 Arista Networks, Inc. All rights reserved.
# ------------------------------------------------------------------------------
#  Author:
#    fdk-support@arista.com
#
#  Description:
#    Package file required for MOS TerminAttr example.
#
#    Licensed under BSD 3-clause license:
#      https://opensource.org/licenses/BSD-3-Clause
#
#  Tags:
#    license-bsd-3-clause
#
# ------------------------------------------------------------------------------

# the build system fills this in.
from __future__ import absolute_import, print_function

from terminattr import libapp

__version__ = "UNVERSIONED"
__buildid__ = 0

app_name = "terminattr"

if not libapp.IS_EOS:
    print("Warning: MOS is not supported by this application")
