#!/usr/bin/env python
import sys
sys.path.insert(0, "<path-to>/tlsauth/env/")
sys.path.insert(0, "<path-to>/tlsauth/flask-demo")

activate_this = '<path-to>/tlsauth/env/bin/activate_this.py'
execfile(activate_this, dict(__file__=activate_this))

from webapp import app as application
#application.run(debug=True)
