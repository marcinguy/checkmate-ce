from .analyzer import InsiderseckotlinAnalyzer
from .issues_data import issues_data

analyzers = {
    'insiderseckotlin':
        {
            'name': 'insiderseckotlin',
            'title': 'insiderseckotlin',
            'class': InsiderseckotlinAnalyzer,
            'language': 'kotlin',
            'issues_data': issues_data,
        },
}

