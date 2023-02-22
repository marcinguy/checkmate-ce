from .analyzer import SemgrepjavaAnalyzer
from .issues_data import issues_data

analyzers = {
    'semgrepjava':
        {
            'name': 'semgrepjava',
            'title': 'semgrepjava',
            'class': SemgrepjavaAnalyzer,
            'language': 'java',
            'issues_data': issues_data,
        },
}
