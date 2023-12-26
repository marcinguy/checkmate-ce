from .analyzer import FluidAttacksAnalyzer
from .issues_data import issues_data

analyzers = {
    'fluidattacksscannergolang':
        {
            'name': 'fluidattacksscannergolang',
            'title': 'fluidattacksscannergolang',
            'class': FluidAttacksAnalyzer,
            'language': 'golang',
            'issues_data': issues_data,
        },
}
