from .analyzer import FluidAttacksAnalyzer
from .issues_data import issues_data

analyzers = {
    'fluidattacksscannerswift':
        {
            'name': 'fluidattacksscannerswift',
            'title': 'fluidattacksscannerswift',
            'class': FluidAttacksAnalyzer,
            'language': 'swift',
            'issues_data': issues_data,
        },
}
