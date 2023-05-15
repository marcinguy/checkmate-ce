from .analyzer import FluidAttacksAnalyzer
from .issues_data import issues_data

analyzers = {
    'fluidattacksjavascript':
        {
            'name': 'fluidattacksjavascript',
            'title': 'fluidattacksjavascript',
            'class': FluidAttacksAnalyzer,
            'language': 'javascript',
            'issues_data': issues_data,
        },
}
