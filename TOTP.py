# Jahus
# 2018-02-05 23:52
#
# Documentation:
#   https://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm
#   HOTP (RFC 4226) https://tools.ietf.org/html/rfc4226
#
# 2023-11-21: Updated to Python 3, after all these years.
#

import time
import hmac, hashlib, base64
import sys
import argparse


__debug = False


def int_to_bytestring(i, padding=8):
	"""
	Turns an integer to the OATH specified
	bytestring, which is fed to the HMAC
	along with the secret
	"""
	result = bytearray()
	while i != 0:
		result.append(i & 0xFF)
		i >>= 8
	# It's necessary to convert the final result from bytearray to bytes
	# because the hmac functions in python 2.6 and 3.3 don't work with
	# bytearray
	return bytearray(reversed(result)).rjust(padding, b'\0')


def key_check(key):
	key = key.replace('-', '').replace(' ', '')
	missing_padding = len(key) % 8
	if missing_padding != 0:
		key += '=' * (8 - missing_padding)
	return base64.b32decode(key, casefold=True)


def get_key(k, t0=0, ti=30, h_alg=hashlib.sha1, n=6):
	try:
		k = key_check(k)
		# Step 1: Calculate C, number of times TI has elapsed after T0.
		_c = int((time.time()-t0)/ti)
		if __debug: print("C = %i" % _c)
		# Step 2: Compute the HMAC hash H with C as the message and K as the key
		# (the HMAC algorithm is defined in the previous section, but also most cryptographical libraries support it).
		# K should be passed as it is,
		# C should be passed as a raw 64-bit unsigned integer.
		_hmac = hmac.new(key=k, msg=int_to_bytestring(_c), digestmod=h_alg)
		if __debug: print("H = " + _hmac.hexdigest())
		_hmac_digest = int(_hmac.hexdigest(), 16)
		# Step 3:
		# Take the least 4 significant bits of H and use it as an offset, O.
		_mask = (2**(2*2))-1
		_offset = (_hmac_digest >> 0) & _mask
		if __debug: print("O = " + str(_offset))
		# Step 4 :
		# Take 4 bytes from H starting at O bytes MSB,
		# discard the most significant bit and store the rest as an (unsigned) 32-bit integer, I.
		_mask = ((2**(8*4))-1) << ((20 - _offset - 4) * 8)
		if __debug: print("_mask = 0x%x" % _mask)
		_i = (_hmac_digest & _mask) >> ((20 - _offset - 4) * 8)
		if __debug: print("_res = 0x%x" % _i)
		_mask = 0x7fffffff
		_i = _i & _mask
		if __debug: print("_i = 0x%x\n_i = %i" % (_i,_i))
		# Step 5:
		# The token is the lowest N digits of I in base 10.
		# If the result has fewer digits than N, pad it with zeroes from the left.
		_token = _i % 10**n
		if __debug: print("_token = %i" % _token)
		# Check if n digits are returned
		_token_str = str(_token)
		if len(_token_str) < n:
			_token_str = ('0' * (n - len(_token_str))) + _token_str
		return {"success": True, "result": _token_str}
	except Exception as e:
		return {"success": False, "message": str(e)}


if __name__ == "__main__":
	_parser = argparse.ArgumentParser(description='Generate a TOTP token.')
	# Define optional arguments
	_parser.add_argument('-i', '--init', type=int, default=0, help='The Unix time to start counting time steps (default: 0)', metavar="INITIAL_TIME")
	_parser.add_argument('-s', '--step', type=int, default=30, help='The time step in seconds (default: 30)', metavar="TIME_STEP")
	_parser.add_argument('-d', '--digits', type=int, default=6, help='The number of digits in the token (default: 6)', metavar="DIGITS")
	_parser.add_argument('-a', '--alg', default='SHA1', choices=['SHA1', 'SHA256', 'SHA512'], help='The hashing algorithm (default: SHA1)', metavar="HASH_ALGORITHM")
	_parser.add_argument('-v', '--verbose', action="store_true", help="Show debug messages")
	# Define the secret key as a positional argument
	_parser.add_argument('key', nargs='*', help='Secret key (spaces and dashes are tolerated)', metavar="KEY")
	
	_args = _parser.parse_args()
	
	# Convert alg to the actual hashlib algorithm
	hash_algorithms = {
		'SHA1': hashlib.sha1,
		'SHA256': hashlib.sha256,
		'SHA512': hashlib.sha512,
	}
	
	__debug = _args.verbose
	
	try:
		_result = get_key(k=''.join(_args.key), t0=_args.init, ti=_args.step, h_alg=hash_algorithms[_args.alg.upper()], n=_args.digits)
		if _result["success"]:
			print(_result["result"])
		else:
			print("Error\n\t%s" % _result["message"])
	except Exception as e:
		print(e)
		print("Incorrect arguments.\nUse:\n\ttotp \"SICRET_KEY\"")
