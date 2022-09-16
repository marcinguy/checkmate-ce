# -*- coding: utf-8 -*-


from checkmate.lib.analysis.base import BaseAnalyzer

import logging
import os
import tempfile
import json
import subprocess

logger = logging.getLogger(__name__)


class SemgrepDeFiAnalyzer(BaseAnalyzer):

    def __init__(self, *args, **kwargs):
        super(SemgrepDeFiAnalyzer, self).__init__(*args, **kwargs)
        try:
            result = subprocess.check_output(
                ["python3", "-m", "semgrep", "--version"])
        except subprocess.CalledProcessError:
            logger.error(
                "Cannot initialize semgrep analyzer: Executable is missing, please install it.")
            raise

    def summarize(self, items):
        pass

    def analyze(self, file_revision):
        issues = []
        tmpdir = "/tmp/"+file_revision.project.pk

        if not os.path.exists(os.path.dirname(tmpdir+"/"+file_revision.path)):
            try:
                os.makedirs(os.path.dirname(tmpdir+"/"+file_revision.path))
            except OSError as exc:  # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise
        f = open(tmpdir+"/"+file_revision.path, "w")

        fout = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        result = {}
        try:
            with f:
                f.write(file_revision.get_file_content().decode("utf-8"))
            try:
                result = subprocess.check_output(["python3", "-m", "semgrep",
                                                  "--config",
                                                  "/root/semgrep-smart-contracts/",
                                                  "--no-git-ignore",
                                                  "--json",
                                                  f.name])
            
            except subprocess.CalledProcessError as e:
                if e.returncode == 4:
                    result = e.output
                elif e.returncode == 3:
                    result = []
                    pass
                else:
                    result = e.output
                    pass

            
            try:
                json_result = json.loads(result)

                for issue in json_result['results']:

                    location = (((issue['start']['line'], None),
                                 (issue['start']['line'], None)),)

                    if ".sol" in file_revision.path:
                        if issue['check_id'] == "root.semgrep-smart-contracts.solidity.compound-borrowfresh-reentrancy":
                            issue['check_id'] = "compound-borrowfresh-reentrancy"
                        if issue['check_id'] == "root.semgrep-smart-contracts.solidity.compound-sweeptoken-not-restricted":
                            issue['check_id'] = "compound-sweeptoken-not-restricted"
                        if issue['check_id'] == "root.semgrep-smart-contracts.solidity.erc20-public-transfer":
                            issue['check_id'] = "erc20-public-transfer"
                        if issue['check_id'] == "root.semgrep-smart-contracts.solidity.erc20-public-burn":
                            issue['check_id'] = "erc20-public-burn"
                        if issue['check_id'] == "root.semgrep-smart-contracts.solidity.erc677-reentrancy":
                            issue['check_id'] = "erc677-reentrancy"
                        if issue['check_id'] == "root.semgrep-smart-contracts.solidity.erc777-reentrancy":
                            issue['check_id'] = "erc777-reentrancy"
                        if issue['check_id'] == "root.semgrep-smart-contracts.solidity.erc721-reentrancy":
                            issue['check_id'] = "erc721-reentrancy"
                        if issue['check_id'] == "root.semgrep-smart-contracts.solidity.gearbox-tokens-path-confusion":
                            issue['check_id'] = "gearbox-tokens-path-confusion"
                        if issue['check_id'] == "root.semgrep-smart-contracts.solidity.keeper-network-oracle-manipulation":
                            issue['check_id'] = "keeper-network-oracle-manipulation"
                        if issue['check_id'] == "root.semgrep-smart-contracts.solidity.basic-oracle-manipulation":
                            issue['check_id'] = "basic-oracle-manipulation"
                        if issue['check_id'] == "root.semgrep-smart-contracts.solidity.redacted-cartel-custom-approval-bug":
                            issue['check_id'] = "redacted-cartel-custom-approval-bug"
                        if issue['check_id'] == "root.semgrep-smart-contracts.solidity.rigoblock-missing-access-control":
                            issue['check_id'] = "rigoblock-missing-access-control"
                        if issue['check_id'] == "root.semgrep-smart-contracts.solidity.oracle-price-update-not-restricted":
                            issue['check_id'] = "oracle-price-update-not-restricted"
                        if issue['check_id'] == "root.semgrep-smart-contracts.solidity.superfluid-ctx-injection":
                            issue['check_id'] = "superfluid-ctx-injection"
                        if issue['check_id'] == "root.semgrep-smart-contracts.solidity.tecra-coin-burnfrom-bug":
                            issue['check_id'] = "tecra-coin-burnfrom-bug"
                        issues.append({
                            'code': issue['check_id'],
                            'location': location,
                            'data': issue['extra']['message'],
                            'fingerprint': self.get_fingerprint_from_code(file_revision, location, extra_data=issue['extra']['message'])
                        })
            except:
                pass

        finally:
            return {'issues': issues}
