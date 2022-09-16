from .analyzer import BrakemanAnalyzer
from .issues_data import issues_data

analyzers = {
    'brakeman':
        {
            'name': 'Brakeman',
            'title': 'Brakeman',
            'class': BrakemanAnalyzer,
            'language': 'all',
            'issues_data': issues_data,
        },
}
