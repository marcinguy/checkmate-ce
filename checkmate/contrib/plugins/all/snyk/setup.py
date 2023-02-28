from .analyzer import SnykAnalyzer
from .issues_data import issues_data

analyzers = {
    'snyk':
        {
            'name': 'snyk',
            'title': 'snyk',
            'class': SnykAnalyzer,
            'language': 'all',
            'issues_data': issues_data,
        },
}
