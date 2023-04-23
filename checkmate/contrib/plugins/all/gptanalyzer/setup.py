from .analyzer import GptAnalyzer
from .issues_data import issues_data

analyzers = {
    'gptanalyzer':
        {
            'name': 'gptanalyzer',
            'title': 'gptanalyzer',
            'class': GptAnalyzer,
            'language': 'all',
            'issues_data': issues_data,
        },
}
