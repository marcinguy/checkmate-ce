from .analyzer import FluidAttacksAnalyzer
from .issues_data import issues_data

analyzers = {
    'fluidattacksjava':
        {
            'name': 'fluidattacksjava',
            'title': 'fluidattacksjava',
            'class': FluidAttacksAnalyzer,
            'language': 'java',
            'issues_data': issues_data,
        },
}
