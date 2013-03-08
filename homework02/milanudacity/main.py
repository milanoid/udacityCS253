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
<html>
  <head>
    <title>Unit 2 Rot 13</title>
  </head>
  <body>
    <h2>Enter some text to ROT13:</h2>
    <form method="post">
      <textarea name="text" style="height: 100px; width: 400px;">%(rot13text)s</textarea>
      <br>
      <input type="submit">
    </form>
  </body>
</html>
"""

homepage = """
<html>
    <head>
        <title>Milanoid's CS253 page</title>
    </head>
    <body>
        <ul>
            <li>
                <a href="/rot13">ROT13</a>
            </li>
        </ul>
    </body>
</html>
"""

class HomePage(webapp2.RequestHandler):
    def get(self):
        self.response.out.write(homepage)

 

class Rot13(webapp2.RequestHandler):
    def rot13(self, astring):
        
        rot13text = []
        
        for char in astring:
            if not char.isalpha():
                # non-alpha chars simply append as it is without rot13
                rot13text.append(char)
            else:
                # alpha chars modify
                if char.isupper():
                    # modify 'A' (65) to 'Z' (90)
                    if (ord(char) + 13 > 90):
                        # e.g. ord('Z') + 13 = 103 would be 'g' which is not ROT13
                        rot13text.append(chr(ord(char) - 13))
                    else:
                        rot13text.append(chr(ord(char) + 13))
                elif char.islower():
                    # modify 'a' (97) to 'z' (122)
                    if (ord(char) + 13 > 122):
                        # e.g. ord('z') + 13 = 135 would be '\x87' which is not ROT13
                        rot13text.append(chr(ord(char) - 13))
                    else:
                        rot13text.append(chr(ord(char) + 13))

        return "".join(rot13text)


    def write_form(self, form, rot13text=""):
        self.response.out.write(form % {"rot13text": cgi.escape(rot13text, True)})

    def get(self):
            self.response.out.write(self.write_form(form))

    def post(self):
        input_text = self.request.get("text")
        rot13text = self.rot13(input_text)
        self.response.out.write(self.write_form(form, rot13text))
        

                
app = webapp2.WSGIApplication([
    ('/', HomePage),
    ('/rot13', Rot13)
], debug=True)
