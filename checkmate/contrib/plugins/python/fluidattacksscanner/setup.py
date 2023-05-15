from .analyzer import FluidAttacksAnalyzer
from .issues_data import issues_data

analyzers = {
    'fluidattackspython':
        {
            'name': 'fluidattackspython',
            'title': 'fluidattackspython',
            'class': FluidAttacksAnalyzer,
            'language': 'python',
            'issues_data': issues_data,
        },
}
