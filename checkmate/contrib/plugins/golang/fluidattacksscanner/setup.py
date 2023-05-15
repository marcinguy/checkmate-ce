from .analyzer import FluidAttacksAnalyzer
from .issues_data import issues_data

analyzers = {
    'fluidattacksgolang':
        {
            'name': 'fluidattacksgolang',
            'title': 'fluidattacksgolang',
            'class': FluidAttacksAnalyzer,
            'language': 'golang',
            'issues_data': issues_data,
        },
}
