from .analyzer import InsiderseccsharpAnalyzer
from .issues_data import issues_data

analyzers = {
    'insiderseccsharp':
        {
            'name': 'insiderseccsharp',
            'title': 'insiderseccsharp',
            'class': InsiderseccsharpAnalyzer,
            'language': 'all',
            'issues_data': issues_data,
        },
}

