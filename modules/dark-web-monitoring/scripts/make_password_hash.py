#!/usr/bin/env python3
"""Prints a bcrypt hash for ADMIN_PASSWORD_HASH."""
import getpass

import bcrypt

pw = getpass.getpass("Password: ")
print(bcrypt.hashpw(pw.encode(), bcrypt.gensalt(12)).decode())
