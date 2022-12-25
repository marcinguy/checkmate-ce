from .analyzer import OSVscannerAnalyzer
from .issues_data import issues_data

analyzers = {
    'osvscanner':
        {
            'name': 'osvscanner',
            'title': 'osvscanner',
            'class': OSVscannerAnalyzer,
            'language': 'all',
            'issues_data': issues_data,
        },
}
