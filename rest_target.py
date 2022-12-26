#!/usr/bin/env python
from __future__ import print_function

#
# Rest Target for Peach Class
#

'''
Copyright 2017-2020 Peach Tech

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''

from flask import jsonify
from flask import Flask, request
from flask_cors import CORS, cross_origin
from flask_restful import Resource, Api, abort, reqparse
from twisted.web.wsgi import WSGIResource
from twisted.web.server import Site
from twisted.python import log
from twisted.internet import reactor, ssl
from werkzeug.exceptions import HTTPException
from werkzeug.debug import DebuggedApplication
import sqlite3
import logging
import logging.handlers
import random
import os
import sys

logger = logging.getLogger(__name__)

def GetConnection():
	return sqlite3.connect("rest_target.db")

def CreateDb():
	logger.info("Creating in-memory database.")
	conn = GetConnection()
	try:
		c = conn.cursor()
		c.execute('drop table if exists users')
		c.execute('''create table users (user_id integer primary key, user text unique, first text, last text, password text)''')
		c.execute('''insert into users (user, first, last, password) values ('admin', 'Joe', 'Smith', 'Password!')''')

		user_id = str(c.lastrowid)

		c.execute('drop table if exists msgs')
		c.execute('''create table msgs (msg_id integer primary key, from_id int, to_id int, subject text, msg text)''')
		c.execute('''insert into msgs (from_id, to_id, subject, msg) values ('''+user_id+''','''+user_id+''', 'Hello From Myself', 'Welcome to the system...!')''')
		conn.commit()
	except Exception as e:
		logger.error('Error creating user: ' + str(e))
		raise e
	finally:
		conn.close()

app = Flask(__name__)
api = Api(app)
CORS(app, resources = {r"/api/users": {"origins": "*"}})
@app.route("/")
def Home():
	with open('rest_target.html', 'r') as myfile:
		data=myfile.read()
	
	return data, 200, {'Content-Type':'text/html'}

@app.route("/api/.htaccess")
def FakeHtAccess():
	data = "look out, it's an .htaccess file!"
	return data, 200, {'Content-Type':'text/html'}

@app.after_request
def apply_caching(response):
	response.headers["X-Powered-By"] = "PHP/7.0.11"
	return response


class ApiRoot(Resource):
	def get(self):
		return [
			'/api/users'
		]

class ApiCleanDb(Resource):
	def get(self):
		CreateDb()

class ApiUsers(Resource):
	
	def validateToken(self):
		try:
			if request.headers.get('Authorization') == "Token b5638ae7-6e77-4585-b035-7d9de2e3f6b3":
				return True
		except:
			pass
		
		return False
	
	def get(self):
		# Comment out auth check to trigger chail failure
		#if not self.validateToken():
		#    abort(401)
		
		logger.info("Getting all users")
		
		conn = GetConnection()
		users = []
		try:
			c = conn.cursor()
			for row in c.execute("select user_id, user, first, last, password from users"):
				user = {
					"user_id" : row[0],
					"user" : row[1],
					"first" : row[2],
					"last" : row[3],
					"password" : row[4],
				}
				
				users.append(user)
				
		except HTTPException as e:
			raise e
		except Exception as e:
			logger.error('Error getting users: ' + str(e))
			abort(500)
		finally:
			conn.close()
		
		return users, 200
		
	def post(self):
		if not self.validateToken():
			abort(401)

		if request.is_json:
			data = request.get_json(force=True)
		else:
			data = request.form
		
		if len(data['user']) > 1024 or len(data['first']) > 1024 or len(data['last']) > 1024 or len(data['password']) > 1024:
			abort(400)

		logger.info("Creating new user '%s'" % data["user"])
		
		if data['user'] == "\"":
			# Trigger sensitive information disclosure checks
			return "Blah blah blah. Powered by: ASPX.NET Other other other", 200, {'Content-Type':'text/html'}
		elif data['first'] == "\"":
			return """Blah blah blah. Version: 1.1.1 Other other 
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
askjdlaskjdlaksjdlaksjdlaksjdlakjsdlakjsdlkjasldkjalskdjalksjdalskdj
				other""", 200, {'Content-Type':'text/html'}
		elif data['last'] == "\"":
			return "Blah blah blah Stack trace: xxxxxx Ohter other other", 200, {'Content-Type':'text/html'}
		
		user_id = -1
		conn = GetConnection()
		try:
			c = conn.cursor()
			c.execute("insert into users (user, first, last, password) values ('%s', '%s', '%s', '%s')" % (
				data['user'], data['first'], data['last'], data['password'] ))
			user_id = c.lastrowid
			conn.commit()
			
			return {'user_id': user_id}, 201
		
		except HTTPException as e:
			raise e
		except Exception as e:
			logger.error('Error creating user: ' + str(e))
			abort(500)
		finally:
			conn.close()
	
	def delete(self):
		if not self.validateToken():
			abort(401)
		
		user = request.args.get('user')
		
		logging.info("Deleting user %s" % user)
		
		conn = GetConnection()
		try:
			c = conn.cursor()
			c.execute("delete from users where user = '%s'" % user)
			
			if c.rowcount == 0:
				abort(404, message = "User not found.")
			
			conn.commit()
			
			return {'user': user}, 204
		
		except HTTPException as e:
			raise e
		except Exception as e:
			logger.error('Error deleting user: %s' % (user, str(e)))
			abort(500, message="Error deleteing user")
		finally:
			conn.close

class ApiUser(Resource):
	def validateToken(self):
		try:
			if request.headers.get('Authorization') == "Token b5638ae7-6e77-4585-b035-7d9de2e3f6b3":
				return True
		except:
			pass
		
		return False

	@cross_origin(supports_credentials=True, vary_header=False)
	def get(self, user_id):
		if not self.validateToken():
			abort(401)
		
		logging.info("Getting user %d" % user_id)
		
		conn = GetConnection()
		try:
			c = conn.cursor()
			for row in c.execute("select user_id, user, first, last, password from users where user_id = %d" % user_id):
				
				return jsonify({
					"user_id" : row[0],
					"user" : row[1],
					"first" : row[2],
					"last" : row[3],
					"password" : row[4],
					"html" : "<b>"+row[3]+"</b>",
				})
			
			if c.rowcount == 0:
				abort(404, message = "User not found.")
			
		except HTTPException as e:
			raise e
		except Exception as e:
			logger.error('Error getting user_id %d: %s' % (user_id, str(e)))
			abort(500)
		finally:
			conn.close()
	
	def put(self, user_id):
		if not self.validateToken():
			abort(401)
		
		json = request.get_json(force=True)
		
		logger.info("Updating user_id %d"%user_id)

		if len(json['user']) > 1024 or len(json['first']) > 1024 or len(json['last']) > 1024 or len(json['password']) > 1024:
			abort(400)
		
		conn = GetConnection()
		try:
			c = conn.cursor()
			c.execute("update users set user = '%s', first = '%s', last = '%s', password = '%s' where user_id = %d" % (
				json['user'], json['first'], json['last'], json['password'], user_id ))
			
			if c.rowcount == 0:
				logger.warning("User id not found while updating %d" % user_id)
				abort(404, message = "User not found.")
			
			conn.commit()
			
			return {'user_id': user_id}, 204
		
		except HTTPException as e:
			raise e
		except Exception as e:
			logger.error('Error creating user: ' + str(e))
			abort(500)
		finally:
			conn.close()
	
	def delete(self, user_id):
		if not self.validateToken():
			abort(401)
		
		logging.info("Deleting user %d" % user_id)
		
		conn = GetConnection()
		try:
			c = conn.cursor()
			c.execute("delete from users where user_id = %d" % user_id)
			
			if c.rowcount == 0:
				abort(404, message = "User not found.")
			
			conn.commit()
			
			return {'user_id': user_id}, 204
		
		except HTTPException as e:
			raise e
		except Exception as e:
			logger.error('Error deleting user_id: %s' % (user_id, str(e)))
			abort(500, message="Error deleteing user")
		finally:
			conn.close

api.add_resource(ApiRoot,  '/api')
api.add_resource(ApiCleanDb, '/api/cleandb')
api.add_resource(ApiUsers, '/api/users')
api.add_resource(ApiUser,  '/api/users/<int:user_id>')

app = DebuggedApplication(app, evalex=True)

if __name__ == '__main__':
	logger.setLevel(logging.DEBUG)
	
	logDest = (os.environ.get('SYSLOG_TARGET', 'localhost'), logging.handlers.SYSLOG_UDP_PORT)
	logFormatter = logging.Formatter("%(asctime)s [%(levelname)-5.5s] %(message)s")
	syslogHandler = logging.handlers.SysLogHandler(logDest)
	syslogHandler.setFormatter(logFormatter)
	logger.addHandler(syslogHandler)
	
	consoleHandler = logging.StreamHandler()
	consoleHandler.setFormatter(logFormatter)
	logger.addHandler(consoleHandler)
	
	fileHandler = logging.FileHandler('rest_target.log')
	fileHandler.setFormatter(logFormatter)
	logger.addHandler(fileHandler)

	logger.info("syslog destination: %s" % str(logDest))
	logger.info("rest_target.py initializing.")
	CreateDb()
	logger.info("Starting REST application")

	# Enable twisted log messages
	log.startLogging(sys.stdout)

	resource = WSGIResource(reactor, reactor.getThreadPool(), app)
	site = Site(resource)

	reactor.listenTCP(7777, site)
	reactor.listenSSL(7778, site, ssl.DefaultOpenSSLContextFactory('certs/server-key.pem', 'certs/server-cert.pem'))
	reactor.run()

# end
