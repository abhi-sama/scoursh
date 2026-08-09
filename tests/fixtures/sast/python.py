# tests/fixtures/sast/python.py - true-positive fixture for
# modules/sast/rules/python.rules (tests/suites/sast.sh), covering every
# check EXCEPT the eval/exec and yaml.load ones, which reuse
# tests/fixtures/vuln/app.py (already shipped by docs/DESIGN.md §13 step 1)
# rather than duplicating that fixture.

import os
import pickle
import subprocess


def load_session(blob):
    return pickle.load(blob)


def run(cmd):
    return subprocess.run(cmd, shell=True)


def cleanup(path):
    os.system("rm " + path)


app.run(debug=True)

env = Environment(autoescape=False)
