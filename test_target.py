#!/usr/bin/env python

'''Actual unit tests for Flask Sample API

These tests are meant to ensure that the sample API "works"
correctly.  Some tests ensure that it is actually defective
in specific ways which should be hard-coded into the API.

To run these tests, rest_target.py must be running
either on 127.0.0.1:7777 or the URL stored in 
the environment variable TARGET_URL

'''

from __future__ import print_function
import pytest, os, json
from requests import put, get, delete, post

# HTTP target
target = os.getenv('TARGET_URL', 'http://127.0.0.1:7777')
req_args = { 
	# verify disabled server TLS cert verification
	'verify':False,
	# our example can use client cert auth, this sets our user cert.
	#'cert' : (cert_dir % 'client-cert.pem', cert_dir % 'client-key.pem'), 
	'headers':{
		# our example requires an API token for authentication.
		"Authorization":"Token b5638ae7-6e77-4585-b035-7d9de2e3f6b3"
	}
}

def setup_function(self):
	'''
	Setup the test by clearing out created users.
	'''
	
	try:
		delete(target+'/api/users/2', **req_args)
	except:
		pass
	try:
		delete(target+'/api/users?user=dd', **req_args)
	except:
		pass

def teardown_function(self):
	'''
	Teardown test by clearing out created users.
	'''
	
	try:
		delete(target+'/api/users/2', **req_args)
	except:
		pass
	try:
		delete(target+'/api/users?user=dd', **req_args)
	except:
		pass

def test_users_getall():
	get(target+'/api/users', **req_args)

def test_user_create_json():
	# application/json
	r = post(target + '/api/users',
		json={"user":"dd", "first":"mike", "last":"smith", "password":"hello"},
		**req_args)
	assert r.status_code == 201
	user = r.json()
	get(target + '/api/users', **req_args)
	ur = get(target + '/api/users/%d' % user['user_id'], **req_args)
	user2 = ur.json()
	assert user2['first'] == 'mike'
	assert ur.status_code == 200
	dres = delete(target + '/api/users/%d' % user['user_id'], **req_args)
	assert dres.status_code == 204

def test_user_create_form():
	# application/x-www-form-urlencoded
	r = post(target + '/api/users',
		data={"user":"dd", "first":"mike", "last":"smith", "password":"hello"},
		**req_args)
	assert r.status_code == 201
	user = r.json()
	res = get(target + '/api/users', **req_args)
	assert res.status_code == 200
	ur = get(target + '/api/users/%d' % user['user_id'], **req_args)
	assert ur.status_code == 200
	user2 = ur.json()
	assert user2['last'] == 'smith'
	dres = delete(target + '/api/users/%d' % user['user_id'], **req_args)
	assert dres.status_code == 204

def test_user_update():
	r = post(target + '/api/users',
		json={"user":"dd", "first":"mike", "last":"smith", "password":"hello"},
		**req_args)
	assert r.status_code == 201
	user = r.json()
	ur = get(target + '/api/users/%d' % user['user_id'], **req_args)
	assert ur.status_code == 200
	user2 = ur.json()
	
	pres = put(target + '/api/users/%d' % user['user_id'],
		data=json.dumps({"user":"dd", "first":"mike changed", "last":"smith", "password":"hello"}),
		**req_args)
	assert pres.status_code == 204

	ur2 = get(target + '/api/users/%d' % user['user_id'], **req_args)
	user3 = ur2.json()
	assert user2['first'] != user3['first']
	delete(target + '/api/users/%d' % user['user_id'], **req_args)
	get(target + '/api/users', **req_args)

def test_fake_htaccess_exists():
	r = get(target + '/api/.htaccess')
	assert r.status_code == 200


if __name__ == "__main__":
	print()
	print("This script is intended to be run using pytest module.")
	print("Please see README for more information.")
	print()
	print("Example usage with pytest and pytest-peach:")
	print()
	print("  pytest test_target.py --peach=on")
	print()

# end
