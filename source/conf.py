# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
# import os
# import sys
# sys.path.insert(0, os.path.abspath('.'))

# -- Project information -----------------------------------------------------

project = 'web and binary security'
copyright = '2020, Surreal'
author = 'Surreal'

version = u'1.0.0'

release = u'1.0.0'

# The full version, including alpha/beta/rc tags
release = '_build'

# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
import sphinx_rtd_theme
extensions = [
    'sphinx.ext.todo',
    'sphinx.ext.ifconfig',
	'sphinx.ext.autosectionlabel'
]

autosectionlabel_prefix_document = True
autosectionlabel_maxdepth = 3

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = []

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'sphinx'

# If true, `todo` and `todoList` produce output, else they produce nothing.
todo_include_todos = True


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#

html_last_updated_fmt = '%b %d, %Y'
html_domain_indices = True
html_logo = "_static/logo.png"
html_theme = "sphinx_rtd_theme"
html_theme_path = [sphinx_rtd_theme.get_html_theme_path()]
html_use_index = True
html_show_sphinx = False

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']

html_style = 'css/my_theme.css'

master_doc = 'index'

latex_engine = 'xelatex'
latex_elements = {
    'papersize': 'a4paper',
    'pointsize': '11pt',
    'title': u'网络安全',
    'releasename': 'wangzihan',
    'author': 'wangzi',
    'preamble': r'''
\usepackage{xeCJK}
\usepackage{fontspec,xunicode}
\setCJKmainfont[BoldFont=STZhongsong, ItalicFont=STKaiti]{STSong}
\setCJKsansfont[BoldFont=STHeiti]{STXihei}
\setCJKmonofont{STFangsong}
\XeTeXlinebreaklocale "zh"
\XeTeXlinebreakskip = 0pt plus 1pt
\parindent 2em
\definecolor{VerbatimColor}{rgb}{0.95,0.95,0.95}
\setcounter{tocdepth}{3}
\renewcommand\familydefault{\ttdefault}
\renewcommand\CJKfamilydefault{\CJKrmdefault}
'''
}
# 设置文档
latex_documents = [
    (master_doc, 'WebSec.tex', u'\\unexpanded{网络安全}',
     u'\\unexpanded{王子翰}', 'manual', True),
]

#latex_docclass = {'howto':'jsarticle','manual' : 'jsbook'}

latex_logo = "_static/logo.png"
#latex_use_parts = False
#latex_show_pagerefs = False

man_pages = [
    (master_doc, 'WebSec', 'websec Documentation',
     [author], 1)
]