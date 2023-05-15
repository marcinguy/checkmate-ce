from .analyzer import FluidAttacksAnalyzer
from .issues_data import issues_data

analyzers = {
    'fluidattackskotlin':
        {
            'name': 'fluidattackskotlin',
            'title': 'fluidattackskotlin',
            'class': FluidAttacksAnalyzer,
            'language': 'kotlin',
            'issues_data': issues_data,
        },
}
