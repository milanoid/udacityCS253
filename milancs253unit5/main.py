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


from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)


class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

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
					self.redirect("/welcome")
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
			self.redirect('/welcome')
		else:
			self.render('login.html', username=username, error='Invalid Login')


class Logout(Handler):
	def get(self):
		# delete cookie
		self.response.delete_cookie('my_cookie_name')

		# redirect
		self.redirect('/signup')

class Welcome(Handler):
	def get(self):
		# name - get from cookie
		cookie = self.request.cookies.get('my_cookie_name')

		# get the cookie and verify
		if cookie:
			cookie_val = check_secure_val(cookie)
			if cookie_val:
				cookie_username = str(cookie_val)
			else:
				self.redirect('/signup')
		else:
			self.redirect('/signup')
		self.render("welcome.html", name = cookie_username)



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



app = webapp2.WSGIApplication([('/blog', BlogHandler),
	('/blog' + '.json', BlogJson),
	('/blog/newpost', NewPostHandler),
	('/signup', SignUp),
    ('/login', Login),
    ('/logout', Logout),
	(r'/blog/(\d+)', Permalink),
	(r'/blog/(\d+)' + '.json', BlogPostJson)
	], debug=True)
