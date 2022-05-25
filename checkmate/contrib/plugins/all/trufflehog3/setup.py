from .analyzer import Trufflehog3Analyzer
from .issues_data import issues_data

analyzers = {
    'trufflehog3':
        {
            'name': 'trufflehog3',
            'title': 'trufflehog3',
            'class': Trufflehog3Analyzer,
            'language': 'all',
            'issues_data': issues_data,
        },
}
