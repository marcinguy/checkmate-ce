from checkmate.lib.stats.helpers import directory_splitter
from checkmate.lib.models import (Project,
                                  Snapshot,
                                  FileRevision,
                                  Issue)
from checkmate.contrib.plugins.git.models import GitSnapshot
from collections import defaultdict

"""
Default settings values
"""

hooks = defaultdict(list)

plugins = {
    'git': 'checkmate.contrib.plugins.git',
    'trufflehog3':  'checkmate.contrib.plugins.all.trufflehog3',
    'trojansource': 'checkmate.contrib.plugins.all.trojansource',
    'metrics': 'checkmate.contrib.plugins.all.metrics',
    'bandit': 'checkmate.contrib.plugins.all.bandit',
    'brakeman': 'checkmate.contrib.plugins.all.brakeman',
    'phpanalyzer':  'checkmate.contrib.plugins.all.progpilot',
    'gosec':  'checkmate.contrib.plugins.all.gosec',
    'confused': 'checkmate.contrib.plugins.all.confused',
    'pmd': 'checkmate.contrib.plugins.all.pmd',
    'semgrep': 'checkmate.contrib.plugins.all.semgrep',
    'semgrepdefi': 'checkmate.contrib.plugins.all.semgrepdefi',
    'semgrepjs': 'checkmate.contrib.plugins.all.semgrepjs',
    'checkov': 'checkmate.contrib.plugins.all.checkov',
    'kubescape': 'checkmate.contrib.plugins.all.kubescape',
    'insidersecswift': 'checkmate.contrib.plugins.all.insidersecswift',
    'insiderseckotlin': 'checkmate.contrib.plugins.all.insiderseckotlin',
    'insiderseccsharp': 'checkmate.contrib.plugins.all.insiderseccsharp',
    'pmdapex': 'checkmate.contrib.plugins.all.pmdapex',
    'semgrepccpp': 'checkmate.contrib.plugins.all.semgrepccpp',
    'semgrepjava': 'checkmate.contrib.plugins.all.semgrepjava',
    'semgrepeslint': 'checkmate.contrib.plugins.all.semgrepeslint',
    'graudit': 'checkmate.contrib.plugins.all.graudit',
}


language_patterns = {
    'all': {
        'name': 'All',
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
    'GitSnapshot': GitSnapshot,
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
