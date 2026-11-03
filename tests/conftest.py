import os
import sys

# Make the repo root importable so `import snaffcore...` works no matter where
# pytest is launched from.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
