from setuptools import setup

from pipenv.project import Project
from pipenv.utils import convert_deps_to_pip


def get_packages_from_Pipfile():
    pipfile = Project(chdir=False).parsed_pipfile
    return convert_deps_to_pip(pipfile['packages'], r=False)


setup(install_requires=get_packages_from_Pipfile())
