from vk import __version__

author = 'Dmitry Voronin'
project = 'vk'
copyright = '2015, Dmitry Voronin'


version = __version__
release = __version__


extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.doctest',
    'sphinx.ext.napoleon',
    'sphinx.ext.viewcode',
]


templates_path = ['_templates']
source_suffix = '.rst'
master_doc = 'index'


language = 'en'
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

html_theme = 'sphinx_rtd_theme'

autodoc_member_order = 'bysource'
