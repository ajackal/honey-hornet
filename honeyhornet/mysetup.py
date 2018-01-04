import sys
import os


def load_search_paths():
    for i, j, y in os.walk(os.getcwd()):
        if str(i).find('__pycache__') == -1:
            sys.path.append(i)


load_search_paths()
