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
import blowfish
import os

class BlockCipher():
	""" BlockCipher takes an algorithm name, key, and initialization vector
	and creates an object that can be used to encrypt and decrypt strings.
	The string is padded to fit the block size and is then encrypted using
	the defined algorithm. Padding is removed after decryption."""
	
	def __init__(self, alg, key=None, iv=None, mode=None):
		self.key = self.set_key(key)
		self.iv = self.set_iv(iv)
		self.mode = mode
		self.algorithm = self.get_algorithm(alg)
		self.bs = self.algorithm.blocksize()

	def get_algorithm(self, alg):
		""" Return an object based on the algorithm name. Supported algorithms
		are:
			blowfish
			
		Other algorithms may be added later."""
		if alg == 'blowfish': return blowfish.Blowfish(self.key)

	def set_key(self, key):
		""" If no key is provided return a random key of 56 bytes."""
		if key == None:
			return os.urandom(56)
		else:
			return key

	def set_iv(self, iv):
		""" If no IV is provided return a random IV of 16 bytes."""
		if iv == None:
			return os.urandom(16)
		else:
			return iv

	def encrypt_str(self, text):
		""" Pad a string to make it evenly divisible by the blocksize then
		encrypt blocksize chunks of the string."""

		plain = self.pad(text)

		cipher = ""
		for i in range(0, len(plain) - 1, self.bs):
			cipher += self.algorithm.encrypt(plain[i:self.bs + i])

		return cipher

	def decrypt_str(self, text):
		""" Decrypt blocksize chunks of a string then unpad the string."""

		plain = ""
		for i in range(0, len(text) - 1 , self.bs):
			plain += self.algorithm.decrypt(text[i:self.bs + i])
	
		return self.unpad(plain)
	
	def pad(self, text):
		""" Pad a string to make the length evenly divisible by the blocksize.
		Strings that are already evenly divisible are padded with a full block
		of padding bytes. The padding byte is the same as the number of padding
		bytes needed."""

		pl = self.bs - (len(text) % self.bs)
		return text + chr(pl) * pl

	
	def unpad(self, text):
		"""Read the last character of the string and turn it into an integer.
		This shows how many padding bytes to remove. In addition, check to see
		if the correct padding bytes were removed. There should be n bytes of
		n. If not we return an error."""
		
		pl = int(text.encode("hex")[-2:])

		if text[-pl:] == text[-1:] * pl:
			text = text[0:len(text) - pl]
		else:
			raise RunTimeError, "Incorrect Padding after decryption."

		return text
