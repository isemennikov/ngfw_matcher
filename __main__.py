# Developed by Ilya Semennikov
import sys
import os

_here = os.path.dirname(os.path.abspath(__file__))  # папка ngfw_matcher/
_root = os.path.dirname(_here)                       # папка в которую делается git clone / (родитель)

# Вставляем родительскую папку первой в путь
for p in [_root, _here]:
    if p in sys.path:
        sys.path.remove(p)
sys.path.insert(0, _root)

from ngfw_matcher.cli.main import main
main()