from setuptools import setup, find_packages

# pyproject.toml is the source of truth
# This setup.py is for backwards compatibility
setup(
    packages=find_packages(where="src"),
    package_dir={"": "src"},
)
