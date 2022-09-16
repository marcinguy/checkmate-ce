from ...lib.repository import Repository
from ..helpers import RepositoryBasedTest

import tempfile
import os
import shutil


class TestRepository(RepositoryBasedTest):

    gzip_filename = "test_repository/d3py.tar.gz"

    def setUp(self):
        super(TestRepository, self).setUp()
        self.repository = Repository(path=self.tmp_project_path)
        self.tmpdir_blank_repo = tempfile.mkdtemp()
        self.blank_repository = Repository(path=self.tmpdir_blank_repo)

    def tearDown(self):
        shutil.rmtree(self.tmpdir_blank_repo)
        super(TestRepository, self).tearDown()

    def test_init(self):

        self.blank_repository.init()
        assert os.path.exists(self.blank_repository.path+"/.git")
        assert os.path.isdir(self.blank_repository.path+"/.git")

    def test_add_remote(self):

        self.blank_repository.init()
        self.blank_repository.add_remote(
            url=self.tmp_project_path, name="my_origin")
        self.blank_repository.get_remotes()
        assert self.blank_repository.get_remotes(
        ) == [{'name': 'my_origin', 'url': self.tmp_project_path}]

    def test_pull_master_from_origin(self):

        self.blank_repository.init()
        self.blank_repository.add_remote(
            url=self.tmp_project_path, name="my_origin")
        self.blank_repository.pull("my_origin", "master")
        set(os.listdir(self.blank_repository.path))
        assert set(['README.md', 'd3py', 'setup.py', 'tests'])\
            .issubset(set(os.listdir(self.blank_repository.path)))

    def test_get_files_in_commit(self):

        commit_sha = 'e29a09687b91381bf96034fcf1921956177c2d54'
        files_in_commit = self.repository.get_files_in_commit(commit_sha)
        valid_files_in_commit = set(['d3py/geoms/bar.py',
                                     'd3py/templates.py',
                                     'd3py/geoms/area.py',
                                     'examples/d3py_line.py',
                                     'd3py/geoms/geom.py',
                                     'd3py/__init__.py',
                                     'examples/d3py_area.py',
                                     'tests/test_javascript.py',
                                     'examples/d3py_scatter.py',
                                     'd3py/geoms/__init__.py',
                                     'examples/d3py_bar.py',
                                     'd3py/geoms/xaxis.py',
                                     '.gitignore',
                                     'd3py/d3.js',
                                     'examples/d3py_vega_scatter.py',
                                     'd3py/networkx_figure.py',
                                     'README.md',
                                     'examples/d3py_multiline.py',
                                     'examples/d3py_vega_line.py',
                                     'setup.py',
                                     'd3py/javascript.py',
                                     'd3py/css.py',
                                     'd3py/geoms/yaxis.py',
                                     'tests/test_figure.py',
                                     'd3py/geoms/line.py',
                                     'd3py/vega.py',
                                     'd3py/d3py_template.html',
                                     'd3py/pandas_figure.py',
                                     'examples/d3py_graph.py',
                                     'd3py/geoms/Readme.md',
                                     'examples/d3py_vega_area.py',
                                     'examples/d3py_vega_bar.py',
                                     'd3py/geoms/point.py',
                                     'd3py/HTTPHandler.py',
                                     'd3py/test.py',
                                     'd3py/vega_template.html',
                                     'd3py/figure.py',
                                     'd3py/geoms/graph.py'])
        assert set([f['path'] for f in files_in_commit]
                   ) == valid_files_in_commit
