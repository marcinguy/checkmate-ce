from .analyzer import ProgpilotAnalyzer
from .issues_data import issues_data

analyzers = {
    'phpanlyzer':
        {
            'name': 'phpanalyzer',
            'title': 'phpanalyzer',
            'class': ProgpilotAnalyzer,
            'language': 'all',
            'issues_data': issues_data,
        },
}
