# -*- coding: utf-8 -*-


from .analze import Command as AnalyzeCommand
from checkmate.lib.code import CodeEnvironment
from .base import BaseCommand

from collections import defaultdict

import sys
import os
import random
import os.path
import copy
import json
import time
import hashlib
import logging

logger = logging.getLogger(__name__)


class Command(AnalyzeCommand):

    """
    Continuously watches a project for changes and analyzes modified file revisions
    """
