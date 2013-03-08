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
import webapp2
import cgi


form = """
<form method="post">
    <label>
        Day
        <input type="text" name="day" value=%(day)s>
    </label>
    <div style="color: red; font-size=20">%(error)s</div>
    <input type="submit">
<form>

"""


class MainHandler(webapp2.RequestHandler):

    def write_form(self, error="", day=""):
        self.response.out.write(form % {"error": cgi.escape(error, True),
                                        "day": cgi.escape(day, True)})

    def valid_day(self, day):
        if day.isdigit():
            day = int(day)
            if day > 0 and day <= 31:
                return True
            else:
                return False
        else:
            return False




    def get(self):
        # self.response.headers['Content-Type'] = 'text/plain'
        self.write_form()

    def post(self):
        user_day = self.request.get("day")

        day = self.valid_day(user_day)

        if not day:
            self.write_form("That doesn't look valid to me, friend.", 
                            user_day)
        else:
            self.redirect("/thanks")

class ThanksHandler(webapp2.RequestHandler):
    def get(self):
        self.response.out.write("Thanks! That's a totally valid day!")    
 
        

                
app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/thanks', ThanksHandler),
], debug=True)
