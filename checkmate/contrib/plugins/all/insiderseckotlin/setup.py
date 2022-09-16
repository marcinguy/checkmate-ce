from .analyzer import InsiderseckotlinAnalyzer
from .issues_data import issues_data

analyzers = {
    'insiderseckotlin':
        {
            'name': 'insiderseckotlin',
            'title': 'insiderseckotlin',
            'class': InsiderseckotlinAnalyzer,
            'language': 'all',
            'issues_data': issues_data,
        },
}

