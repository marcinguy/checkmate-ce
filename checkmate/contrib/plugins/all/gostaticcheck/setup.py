from .analyzer import GostaticcheckAnalyzer
from .issues_data import issues_data

analyzers = {
    'gostaticcheck':
        {
            'name': 'gostaticcheck',
            'title': 'gostaticcheck',
            'class': GostaticcheckAnalyzer,
            'language': 'all',
            'issues_data': issues_data,
        },
}
