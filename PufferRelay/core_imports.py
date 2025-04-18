# Created by Massamba DIOUF
#
# This file is part of PufferRelay.
#
# PufferRelay is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# PufferRelay is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with PufferRelay. If not, see <http://www.gnu.org/licenses/>.
#
# Credits: Portions of this code were adapted from PCredz (https://github.com/lgandx/PCredz)
#         (c) Laurent Gaffie GNU General Public License v3.0.

import pyshark
import sqlite3
import binascii
import urllib.parse
import sys
import os
import logging
import dotenv
import argparse
import base64
import re
import rich
import shutil
import time
import codecs
import struct
import asyncio
from collections import defaultdict
from ipaddress import ip_network, ip_address
from rich.table import Table
from rich.console import Console
from rich.text import Text
from pathlib import Path
from PufferRelay.config import DB_NAME

