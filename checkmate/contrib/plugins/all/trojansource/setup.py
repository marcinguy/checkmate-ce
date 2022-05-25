from .analyzer import TrojansourceAnalyzer
from .issues_data import issues_data

analyzers = {
    'trojansource':
        {
            'name': 'trojansource',
            'title': 'trojansource',
            'class': TrojansourceAnalyzer,
            'language': 'all',
            'issues_data': issues_data,
        },
}
