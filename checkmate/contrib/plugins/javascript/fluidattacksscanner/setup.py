from .analyzer import FluidAttacksAnalyzer
from .issues_data import issues_data

analyzers = {
    'fluidattacksscannerjavascript':
        {
            'name': 'fluidattacksscannerjavascript',
            'title': 'fluidattacksscannerjavascript',
            'class': FluidAttacksAnalyzer,
            'language': 'javascript',
            'issues_data': issues_data,
        },
}
