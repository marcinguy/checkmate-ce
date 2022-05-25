from checkmate.lib.stats.helpers import directory_splitter
from checkmate.lib.models import (Project,
                                  Snapshot,
                                  DiskSnapshot,
                                  FileRevision,
                                  Issue)

from collections import defaultdict

"""
Default settings values
"""

hooks = defaultdict(list)

plugins = {
    # 'pep8' : 'checkmate.contrib.plugins.python.pep8',
    # 'pylint' : 'checkmate.contrib.plugins.python.pylint',
    # 'pyflakes' : 'checkmate.contrib.plugins.python.pyflakes',
    # 'jshint' : 'checkmate.contrib.plugins.javascript.jshint',
    # 'metrics' : 'checkmate.contrib.plugins.python.metrics',
    'git': 'checkmate.contrib.plugins.git',
           # 'bandit' : 'checkmate.contrib.plugins.python.bandit',
           # 'brakeman' : 'checkmate.contrib.plugins.ruby.brakeman',
           # 'phpanalyzer' :  'checkmate.contrib.plugins.php.progpilot',
           'trufflehog3':  'checkmate.contrib.plugins.all.trufflehog3',
           # 'gosec' :  'checkmate.contrib.plugins.golang.gosec',
           # 'confused' : 'checkmate.contrib.plugins.javascript.confused',
           'trojansource': 'checkmate.contrib.plugins.all.trojansource',
           # 'pep8' : 'checkmate.contrib.plugins.all.tpep8',
           # 'pylint': 'checkmate.contrib.plugins.all.pylint',
           # 'pyflakes': 'checkmate.contrib.plugins.all.pyflakes',
           # 'jshint': 'checkmate.contrib.plugins.all.jshint',
           'metrics': 'checkmate.contrib.plugins.all.metrics',
           'bandit': 'checkmate.contrib.plugins.all.bandit',
           'brakeman': 'checkmate.contrib.plugins.all.brakeman',
           'phpanalyzer':  'checkmate.contrib.plugins.all.progpilot',
           'gosec':  'checkmate.contrib.plugins.all.gosec',
           #'confused': 'checkmate.contrib.plugins.all.confused',
           'pmd': 'checkmate.contrib.plugins.all.pmd',
           'semgrep': 'checkmate.contrib.plugins.all.semgrep',
           'semgrepdefi': 'checkmate.contrib.plugins.all.semgrepdefi',
           'semgrepjs': 'checkmate.contrib.plugins.all.semgrepjs',
           'checkov': 'checkmate.contrib.plugins.all.checkov',




}


language_patterns = {
    # 'python':
    # {
    #     'name' : 'Python',
    #     'patterns' : [u'\.py$',u'\.pyw$'],
    # },
    # 'javascript' : {
    #      'name' : 'Javascript',
    #      'patterns' : [u'\.js$',u'package\.json$'],
    # },
    # 'php' : {
    #      'name' : 'PHP',
    #      'patterns' : [u'\.php$'],
    # },
    # 'ruby' : {
    #      'name' : 'Ruby',
    #      'patterns' : [u'\.rb'],
    # },
    # 'golang' : {
    #      'name' : 'Golang',
    #      'patterns' : [u'\.go$'],
    # },

    'all': {
        'name': 'All',
        # 'patterns' : [u'\.yml$',u'\.yaml$',u'\.xml$',u'\.gradle$',u'\.py$',u'\.pyw$',u'\.js$',u'package\.json$',u'\.php$',u'\.rb',u'\.go$'],
        'patterns': ['\.*$'],
    },
}

analyzers = {}

commands = {
    'alembic': 'checkmate.management.commands.alembic.Command',
    'init': 'checkmate.management.commands.init.Command',
    'analyze': 'checkmate.management.commands.analyze.Command',
    'reset': 'checkmate.management.commands.reset.Command',
    'shell': 'checkmate.management.commands.shell.Command',
    'summary': 'checkmate.management.commands.summary.Command',
    'snapshots': 'checkmate.management.commands.snapshots.Command',
    'issues': 'checkmate.management.commands.issues.Command',
    'props': {
        'get': 'checkmate.management.commands.props.get.Command',
        'set': 'checkmate.management.commands.props.set.Command',
        'delete': 'checkmate.management.commands.props.delete.Command'
    }
}

models = {
    'Project': Project,
    'Snapshot': Snapshot,
    'DiskSnapshot': DiskSnapshot,
    'FileRevision': FileRevision,
    'Issue': Issue,
}

aggregators = {
    'directory':
        {
            'mapper': lambda file_revision: directory_splitter(file_revision['path'], include_filename=True)
        }
}

checkignore = """*/site-packages/*
*/dist-packages/*
*/build/*
*/eggs/*
*/migrations/*
*/alembic/versions/*
"""
