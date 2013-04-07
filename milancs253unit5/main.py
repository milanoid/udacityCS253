#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# TODO: replace '\n' with <br> tag in content
# TODO: fix links on /blog, they should point to a specific blog post
# TEST

import os
import jinja2
import webapp2
import json
import hmac
import logging

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)


# cookies security related methods
SECRET = 'imsosecret'

def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
	return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
	val = h.split('|')[0]
	if h == make_secure_val(val):
		return val


class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	# validation functions
	def validate_username(self, username):
		# get all existing users from DB
		users = User.all()

		# Loop through all of them and check
		for user in users:
			#logging.info(user.username)
			if str(user.username) == username:
				logging.info("existing user found: " + str(user.username))
				return False
			else:
				pass
		return True

	def validate_password(self, password):
		# password must be at least 3 chars long
		if len(password) < 3:
			return False
		else:
			return True

		return True
	def validate_vrfypass(self, vrfypass, password):
		return vrfypass == password

	def validate_email(self, email):
		# a dummy verification, does it contain exactly one '@' ?
		return email.count('@') == 1

	def validate_login(self, username, password):
		# users = User.all()

		user = User.all().filter('username =', username).get()
		if user:
			return user.password == password

# Gql model
class Post(db.Model):
	subject = db.StringProperty(required = True)
	date = db.DateTimeProperty(auto_now_add = True)
	content = db.TextProperty(required = True)


class BlogHandler(Handler):
	def render_blog(self):
		posts = db.GqlQuery("SELECT * FROM Post ORDER BY date DESC limit 10") # Gql
		# posts = Post.all().order('-created')
		self.render("blog.html", posts=posts)

	def get(self):
		self.render_blog()

class NewPostHandler(Handler):
	def render_new_post(self, subject="", content="", error=""):
		self.render("newpost.html", subject=subject, content=content, error=error)

	def get(self):
		self.render_new_post()

	def post(self):
		subject = self.request.get("subject")
		content = self.request.get("content")

		if subject and content:
			p = Post(subject = subject, content = content)
			post_key = p.put()
			self.redirect("/blog/%d" % post_key.id(), True)
		else:
			error = "we need both a subject and content"
			self.render_new_post(subject, content, error)




class Permalink(Handler):
	def get(self, post_id):
		post = Post.get_by_id(int(post_id))
		# key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		
		p_id = str(post.key().id())

		if post:
			self.render("blog.html", posts=[post], p_id=p_id)
		else:
			self.error(404)



# Gql model
class User(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	email = db.EmailProperty(required = False)


class SignUp(Handler):
	def get(self):
		self.render("signup.html")

	def post(self):
		user_username = self.request.get("username")
		user_password = self.request.get("password")
		user_vrfypass = self.request.get("verify")
		user_email = self.request.get("email")

		# validate username, password, vrfypass
		if self.validate_username(user_username):
			if self.validate_password(user_password):
				if self.validate_vrfypass(user_vrfypass, user_password):
					
					# validate email
					if user_email:
						if self.validate_email(user_email):
							pass
					else:
						user_email = None

					# store new user into DB
					u = User(username=user_username, password=user_password, email=user_email)
					u.put()

					# make cookie value secure first
					secure_username = make_secure_val(str(user_username))

					# store the secured cookie
					self.response.headers.add_header('Set-Cookie', 'my_cookie_name='+ secure_username +' Path=/')

					# redirect
					self.redirect("/blog/welcome")
				else:
					self.render('signup.html', username=user_username, email=user_email, error_vrfy="Your password didn't match")
			else:
				self.render('signup.html', username=user_username, email=user_email, error_pass="Password error!")

		else:
			self.render('signup.html', username=user_username, email=user_email, error_username='User already exists.')		

class Login(Handler):
	def get(self):
		self.render('login.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		# if the username exists in the DB
		if self.validate_login(username, password):
			# make cookie value secure first
			secure_username = make_secure_val(str(username))

			# store the secured cookie
			self.response.headers.add_header('Set-Cookie', 'my_cookie_name='+ secure_username +' Path=/')
			
			# and redirct
			self.redirect('/blog/welcome')
		else:
			self.render('login.html', username=username, error='Invalid Login')


class Logout(Handler):
	def get(self):
		# delete cookie
		self.response.delete_cookie('my_cookie_name')

		# redirect
		self.redirect('/blog/signup')

class Welcome(Handler):
	def get(self):
		# name - get from cookie
		cookie = self.request.cookies.get('my_cookie_name')

		# get the cookie and verify
		if cookie:
			logging.info("1 - In cookie if !!" + cookie)
			cookie_val = check_secure_val(cookie)
			if cookie_val:
				logging.info("2 - In cookie_val if !!" + cookie)
				cookie_username = str(cookie_val)
				self.render("welcome.html", name = cookie_username)
			else:
				self.redirect('/blog/signup')
		else:
			self.redirect('/blog/signup')
		



class BlogPostJson(Handler):
	def get(self, post_id):
		
		# get the post
		post = Post.get_by_id(int(post_id))	
		p_id = str(post.key().id())

		# prepare string representation of json response
		my_response = {"content" : post.content, "crated" : str(post.date), "subject" : post.subject}

		# dumpt the json string into real json
		json_response = json.dumps(my_response)

		# modify content-type and push json response out
		self.response.headers.add_header('content-type', 'application/json', charset='utf-8')
		self.response.out.write(json_response)

class BlogJson(Handler):
	def get(self):
		# get all blog posts
		posts = db.GqlQuery("SELECT * FROM Post ORDER BY date DESC") # Gql

		# prepare python string representation of json response
		my_response = []
		json_item = {}

		for post in posts:
			json_item = {"content" : post.content, "crated" : str(post.date), "subject" : post.subject}
			my_response.append(json_item)

		# dumpt the json string into real json
		json_response = json.dumps(my_response)

		# modify content-type and push json response out
		self.response.headers.add_header('content-type', 'application/json', charset='utf-8')
		self.response.out.write(json_response)



app = webapp2.WSGIApplication([('/', BlogHandler),
	('/blog', BlogHandler),
	('/blog/.json', BlogJson),
	('/blog/newpost', NewPostHandler),
	('/blog/signup', SignUp),
	('/blog/welcome', Welcome),
    ('/blog/login', Login),
    ('/blog/logout', Logout),
	(r'/blog/(\d+)', Permalink),
	(r'/blog/(\d+)' + '.json', BlogPostJson)
	], debug=True)
