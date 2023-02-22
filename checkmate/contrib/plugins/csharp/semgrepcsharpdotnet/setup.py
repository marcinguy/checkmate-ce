from .analyzer import SemgrepCsharpDotnetAnalyzer
from .issues_data import issues_data

analyzers = {
    'semgrepcsharpdotnet':
        {
            'name': 'semgrepcsharpdotnet',
            'title': 'semgrepcsharpdotnet',
            'class': SemgrepCsharpDotnetAnalyzer,
            'language': 'csharp',
            'issues_data': issues_data,
        },
}
