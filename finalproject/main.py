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
import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

# Super secret code for hashing
secret = 'abcd'

# Handling blog functionality, and a few different functions for rest of blog
def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

def make_secure_val(val):
	return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
	val = secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val

class BlogHandler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		params['user'] = self.user
		return render_str(template, **params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))

def render_post(response, post):
	response.out.write('<b>' + post.subject + '</b><br>')
	response.out.write(post.content)

# No functionality, Used for Reference
class MainPage(BlogHandler):
	def get(self):
		self.write('Hello, Udacity!')


##### Homework 4 - Hashing User information
# Secures user information
def make_salt(length = 5):
	return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
	salt = h.split(',')[0]
	return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
	return db.Key.from_path('users', group)

class User(db.Model):
	name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()

	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid, parent = users_key())

	@classmethod
	def by_name(cls, name):
		u = User.all().filter('name =', name).get()
		return u

	@classmethod
	def register(cls, name, pw, email = None):
		pw_hash = make_pw_hash(name, pw)
		return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

	@classmethod
	def login(cls, name, pw):
		u = cls.by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			return u


##### Homework 2 - Creating the blog
# Handles for blog functionality

def blog_key(name = 'default'):
	return db.Key.from_path('blogs', name)

# Post stored, rendered here
class Post(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	user = db.StringProperty()
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)
	comments = db.StringListProperty()
	likes = db.RatingProperty()
	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("post.html", p = self)

# Liking Posts
	def liking(self, currentUser):
		p = self
		u = currentUser
		all_likes = db.GqlQuery("select * from Like where user= :user and post_reference= :post_ref", user=u, post_ref=p.subject)
		if all_likes.count() < 1:
			l = Like(post_reference=p.subject, user=u)
			l.put()
			p.likes = p.likes + 1
			p.put()

class Like(db.Model):
	post_reference = db.StringProperty(required=True)
	user = db.StringProperty()

class LikePost(BlogHandler):
	def get(self, post_id):
		if self.user:
			key = db.Key.from_path('Post', int(post_id), parent=blog_key())
			post = db.get(key)
		else:
			self.redirect("/login")
			return
		if self.user.name == post.user:
			posts = db.GqlQuery("select * from Post order by created desc limit 10")
			comments = db.GqlQuery("select *  from Comment order by created desc ")
			self.render('/front.html', posts=posts, comments=comments)
			return
		if not post:
			self.error(404)
			return
		post.liking(self.user.name)
		self.redirect('/blog')

# Post comments stored, rendered here
class Comment(db.Model):
	post_reference = db.StringProperty(required=True)
	user = db.StringProperty()
	content = db.TextProperty(required=True)
	created = db.DateTimeProperty(auto_now_add=True)
	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("comment.html", p=self)

# Handles the blogs main page and it's posts
class BlogFront(BlogHandler):
	def get(self):
		posts = greetings = Post.all().order('-created')
		comments = db.GqlQuery("select *  from Comment order by created desc ")
		self.render('front.html', posts = posts, comments = comments)

# When new post made, this function handles it
class PostPage(BlogHandler):
	def get(self, post_id):
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)
		subject = post.subject
		user = self.user.name
		cs = db.GqlQuery("select * from Comment where post_reference = :subject order by created desc", subject=subject)
		if not post:
			self.error(404)
			return

		self.render("permalink.html", post = post, user = user, comments = cs, post_id = subject)

# Allows for new posts, works with above class
class NewPost(BlogHandler):
	def get(self):
		if self.user:
			return self.render("newpost.html")
		else:
			return self.redirect("/login")

	def post(self):
		if not self.user:
			return self.redirect('/blog')

		subject = self.request.get('subject')
		content = self.request.get('content')
		user = self.user.name

		if subject and content:
			p = Post(parent = blog_key(), subject = subject, content = content, likes=0, user = user)
			p.put()
			self.redirect('/blog/%s' % str(p.key().id()))
		else:
			error = "subject and content, please!"
			self.render("newpost.html", subject=subject, user=user, content=content, error=error)

# Next two classes are for editing and deleting posts
class EditPost(BlogHandler):
	def get(self, post_id):
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)
		if not post:
			self.error(404)
			return
		if self.user:
			if self.user.name == post.user:
				subject = post.subject
				content = post.content
				user = self.user.name
				self.render('newpost.html', subject=subject, user = user, content=content, post_id=post_id, task="edit")
			else:
				return self.redirect('/blog')
		else:
			return self.redirect("/login")
	def post(self, post_id):
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)
		if not post:
			self.error(404)
			return
		if not self.user:
			self.redirect('/login.html')
			return
		subject = self.request.get('subject')
		content = self.request.get('content')
		user = self.user.name
		if subject and content:
			if self.user.name == post.user:
				post.subject = subject
				post.content = content
				post.user = user
				post.put()
				self.redirect('/blog/%s' % str(post.key().id()))
			else:
				return self.redirect('/blog')
		else:
			error = "Ensure both fields are filled out"
			self.render('newpost.html', subject=subject, content=content, error=error)

class DeletePost(BlogHandler):
	def get(self, post_id):
		if post_id == "":
			self.redirect("/")
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)
		if not post:
			self.error(404)
			return

		if self.user:
			if self.user.name == post.user:
				db.delete(key)
			posts = db.GqlQuery("select * from Post order by created desc limit 10")
			comments = db.GqlQuery("select *  from Comment order by created desc ")
			self.render('delete-post.html', posts = posts)
			if self.user.name != post.user:
				self.redirect('/blog')
		else:
			self.redirect('/login')
			
# Actual handler for Commenting on posts, uses class Comment to store
class CommentPost(BlogHandler):
	def get(self, post_id):
		if not self.user:
			return self.redirect('/blog')
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)
		if self.user:
			self.render("comment-post.html", subject=post.subject)
		else:
			self.redirect("/login")
	def post(self, post_id):
		if not self.user:
			return self.redirect('/blog')
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)
		subject = post.subject
		content = self.request.get('content')
		user = self.user.name

		if content:
			cs = Comment(parent=blog_key(), post_reference=subject, content=content, user=user, BlogHandler=BlogHandler)
			cs.put()
			self.redirect('/')
		else:
			self.render("comment-post.html", content=content, error=error, task="edit")

# Next two functions handle deleting and editing comments		
class DeleteComment(BlogHandler):
	def get(self, comment_id):
		if comment_id == "":
			return self.redirect("/")
		key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
		comment = db.get(key)
		if not comment:
			self.error(404)
			return
		if self.user:
			if self.user.name == comment.user:
				db.delete(key)
			posts = db.GqlQuery("select * from Post order by created desc limit 10")
			comments = db.GqlQuery("select *  from Comment order by created desc ")
			self.redirect("/blog")
		else:
			self.redirect("/login")
	def post(self, post_id):
		if post_id == "":
			self.redirect("/")
		if not self.user:
			self.redirect('/login.html')
			return
		self.redirect('/')

class EditComment(BlogHandler):
	def get(self, comment_id):
		if comment_id == "":
			return self.redirect("/")
		key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
		comment = db.get(key)
		if not comment:
			self.error(404)
			return
		if self.user:
			if self.user.name == comment.user:
				content = comment.content
				user = self.user
				self.render('comment-post.html', content=content, comment_id=comment_id, task="edit")
			else:
				self.redirect('/blog')
		else:
			self.redirect('/login')

	def post(self, comment_id):
		key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
		comment = db.get(key)
		post = db.get(key)
		if not self.user:
			self.redirect('/login.html')
			return
		if self.user.name == comment.user:
			content = self.request.get('content')
			user = self.user.name
			if content:
				comment.content = content
				comment.put()
				self.redirect('/')
			else:
				error = "Ensure there is content"
				self.render('comment-post.html', content=content, error=error)
		else:
			self.redirect('/blog')

###### From Unit 2 - Signing up and Login info
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
	return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
	def get(self):
		self.render("signup-form.html")

	def post(self):
		have_error = False
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')
		self.email = self.request.get('email')

		params = dict(username = self.username,email = self.email)

		if not valid_username(self.username):
			params['error_username'] = "That's not a valid username."
			have_error = True

		if not valid_password(self.password):
			params['error_password'] = "That wasn't a valid password."
			have_error = True
		elif self.password != self.verify:
			params['error_verify'] = "Your passwords didn't match."
			have_error = True

		if not valid_email(self.email):
			params['error_email'] = "That's not a valid email."
			have_error = True

		if have_error:
			self.render('signup-form.html', **params)
		else:
			self.done()

	def done(self, *a, **kw):
		raise NotImplementedError

class Register(Signup):
	def done(self):
		u = User.by_name(self.username)
		if u:
			msg = 'That user already exists.'
			self.render('signup-form.html', error_username = msg)
		else:
			u = User.register(self.username, self.password, self.email)
			u.put()

			self.login(u)
			self.redirect('/blog')

class Login(BlogHandler):
	def get(self):
		self.render('login-form.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')
		u = User.login(username, password)
		if u:
			self.login(u)
			self.redirect('/blog')
		else:
			msg = 'Invalid login'
			self.render('login-form.html', error = msg)

class Logout(BlogHandler):
	def get(self):
		self.logout()
		self.redirect('/blog')

# Welcome page, many functions redirect to it. Mostly filler information
# Redirects users to sign up if not logged in. Users can still view blog if they wish to.
class Welcome(BlogHandler):
	def get(self):
		if self.user:
			self.render('welcome.html', username = self.user.name)
		else:
			self.redirect('/signup')

app = webapp2.WSGIApplication([('/', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
							   ('/blog/editpost/([0-9]+)', EditPost),
							   ('/blog/deletepost/([0-9]+)', DeletePost),
							   ('/blog/like/([0-9]+)', LikePost),
							   ('/blog/commentpost/([0-9]+)', CommentPost),
							   ('/blog/deletecomment/([0-9]+)', DeleteComment),
							   ('/blog/editcomment/([0-9]+)', EditComment),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout)
                               ],
                              debug=True)
