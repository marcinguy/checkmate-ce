from .analyzer import SemgrepAnalyzer
from .issues_data import issues_data

analyzers = {
    'semgrep':
        {
            'name': 'semgrep',
            'title': 'semgrep',
            'class': SemgrepAnalyzer,
            'language': 'java',
            'issues_data': issues_data,
        },
}
