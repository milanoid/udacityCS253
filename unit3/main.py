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
import re
import os
import jinja2
import webapp2


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
		posts = db.GqlQuery("SELECT * FROM Post ORDER BY date DESC")
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
		self.render("blog.html", posts=[post])


app = webapp2.WSGIApplication([('/blog', BlogHandler),
	('/blog/newpost', NewPostHandler),
	(r'/blog/(\d+)', Permalink)], debug=True)
