from .analyzer import SemgrepccppAnalyzer
from .issues_data import issues_data

analyzers = {
    'semgrepccpp':
        {
            'name': 'semgrepccpp',
            'title': 'semgrepccpp',
            'class': SemgrepccppAnalyzer,
            'language': 'all',
            'issues_data': issues_data,
        },
}
