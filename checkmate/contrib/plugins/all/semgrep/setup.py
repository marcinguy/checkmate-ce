from .analyzer import SemgrepAnalyzer
from .issues_data import issues_data

analyzers = {
    'semgrep':
        {
            'name': 'semgrep',
            'title': 'semgrep',
            'class': SemgrepAnalyzer,
            'language': 'all',
            'issues_data': issues_data,
        },
}
