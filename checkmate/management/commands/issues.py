# -*- coding: utf-8 -*-
from checkmate.lib.models import Issue
from checkmate.contrib.plugins.git.models import GitSnapshot
from checkmate.management.commands.base import BaseCommand
import logging
import json
import requests
import os
from rich.console import Console
from rich.table import Table
from rich import print

logger = logging.getLogger(__name__)


class Command(BaseCommand):

    """
    Returns a list of issues for the current snapshot or file revision.
    """

    def run(self):
        snapshot_pk = None
        filenames = None
        ashtml = 0

        high = ["SQL", "injection", "unauthorized", "forgery", "overflow", "unescaped", "traversal", "overflow", "boundaries", "eval", "attacks"]
        medium = ["insecurely", "insecure", "exec", "cross-site", "XSS", "unsafe", "redirect", "splitting"]
        
        if self.extra_args:
            #if len(self.extra_args) == 1:
            #    snapshot_pk = self.extra_args[0]
            #else:
            #    snapshot_pk, filenames = self.extra_args[0], self.extra_args[1:]
            if self.extra_args[0] == "html":
                ashtml = 1

        if snapshot_pk:
            try:
                snapshot = self.backend.get(GitSnapshot,
                                            {'pk': {'$regex': r'^'+snapshot_pk}})
            except GitSnapshot.DoesNotExist:
                logger.error("Snapshot %s does not exist!" % snapshot_pk)
                return -1
            except GitSnapshot.MultipleDocumentsReturned:
                logger.error("Ambiguous key %s!" % snapshot_pk)
                return -1
        else:
            try:
                snapshot = self.backend.filter(GitSnapshot, {})\
                                       .sort('created_at', -1)[0]
            except IndexError:
                logger.error("No snapshots in this project.")
                return -1

        issues = self.backend.filter(Issue,
                {})\
                             .sort('analyzer',1)


        try:
          r = requests.get("https://dl.betterscan.io/auth?licence="+os.getenv('LIC'))
          if(r.content.decode("utf-8")=="OK"):
            valid=1
          else:
            valid=0
        except:
          valid=0
          pass

        if ashtml == 0:
          table = Table(title="Scan Report")

          table.add_column("Description", style="magenta")
          table.add_column("Severity", justify="right", style="green")
          table.add_column("File", justify="right", style="green")
          table.add_column("Line", justify="right", style="green")

          unique = []
          for issue in issues:
            try:
              if issue["line"]==1:
                unique.append(issue)
              if issue["line"]==0:
                issue["line"]=1
              if all(((unique_issue["line"] != issue["line"]) | (unique_issue["file"] != issue["file"])) for unique_issue in unique):
                unique.append(issue)
            except:
              pass

  
         

          if not valid:
            for issue in unique:
              if not issue['code'] == "AnalysisError":
                try:
                  severity = issue['severity']
                  if issue['severity'] == "High":
                    severity = "[red] High"
                  elif issue['severity'] == "Medium":
                    severity = "[yellow] Medium"
                except:
                  severity = "Warning"

                desc_lower = issue['data'].lower()
                res = [ele for ele in high if(ele in desc_lower)]
                if bool(res) is True:
                 severity = "[red] High"
                res = [ele for ele in medium if(ele in desc_lower)]
                if bool(res) is True:
                  severity = "[yellow] Medium"
                table.add_row(issue['data'], severity, "Please upgrade to PRO", str(issue['line']), "❌")
          else:
            for issue in unique:
              if not issue['code'] == "AnalysisError":
                try:
                  severity = issue['severity']
                  if issue['severity'] == "High":
                    severity = "[red] High"
                  elif issue['severity'] == "Medium":
                    severity = "[yellow] Medium"
                except:
                  severity = "Warning"
                
                desc_lower = issue['data'].lower()
                res = [ele for ele in high if(ele in desc_lower)]
                if bool(res) is True:
                 severity = "[red] High"
                res = [ele for ele in medium if(ele in desc_lower)]
                if bool(res) is True:
                  severity = "[yellow] Medium"
                table.add_row(issue['data'], severity, issue['file'], str(issue['line']), "❌")
          

          console = Console()
          console.print(table)
          print("[bold red]Note:[/bold red] Issues include findings accross all revisions i.e it can be that you have fixed it in your latest revision, but the finding will still appear here (for the affected revision)")
          if not valid:
            print("This scan will have all the features with PRO version :thumbs_up: Limited Lifetime deal with this [link=https://buy.betterscan.io]link[/link] https://buy.betterscan.io")
          else:
            print("Thank you for using the PRO version. :thumbs_up:") 

          #for issue in issues:
          #    print(("%(analyzer)s\t%(code)s\t" % {'analyzer': issue['analyzer'],
          #                                       'code': issue['code']}))
        else:
          jsonout = []
          out = {}
          unique = []
          for issue in issues:
            try:
              if issue["line"]==1:
                unique.append(issue)
              if issue["line"]==0:
                issue["line"]=1
              if all(((unique_issue["line"] != issue["line"]) | (unique_issue["file"] != issue["file"])) for unique_issue in unique):
                unique.append(issue)
            except:
              pass



          if not valid:
              
            for issue in unique:
                if not issue['code'] == "AnalysisError":
                  out={}
                  try:
                    severity = issue['severity']
                  except:
                    severity = "Warning"
                  desc_lower = issue['data'].lower()
                  res = [ele for ele in high if(ele in desc_lower)]
                  if bool(res) is True:
                    severity = "High"
                  res = [ele for ele in medium if(ele in desc_lower)]
                  if bool(res) is True:
                    severity = "Medium"
                  out['hash'] =  issue['hash']
                  out['description'] = issue['data']
                  out['severity'] = severity
                  out['file'] = "Please upgrade to PRO"
                  out['line'] = issue['line']
                  jsonout.append(out)
                  out={}
       

          else:
             for issue in unique:
                if not issue['code'] == "AnalysisError":
                  out={}
                  try:
                    severity = issue['severity']
                  except:
                    severity = "Warning"
                  desc_lower = issue['data'].lower()
                  res = [ele for ele in high if(ele in desc_lower)]
                  if bool(res) is True:
                    severity = "High"
                  res = [ele for ele in medium if(ele in desc_lower)]
                  if bool(res) is True:
                    severity = "Medium"
                  out['hash'] =  issue['hash']
                  out['description'] = issue['data']
                  out['severity'] = severity
                  out['file'] = issue['file']
                  out['line'] = issue['line']
                  jsonout.append(out)
                  out={}
       
   
          head = """
<!DOCTYPE html>
<html>
<head>
  <meta http-equiv="content-type" content="text/html; charset=UTF-8">
  <title>Report</title>
  <script type='text/javascript' src='https://code.jquery.com/jquery-2.1.0.js'></script>

  <script type='text/javascript' src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.1/js/bootstrap.min.js"></script>

  <link href="https://dl.betterscan.io/assets/css/reportstyle.css" rel="stylesheet">





<script type='text/javascript'>//<![CDATA[
$(window).load(function(){
var data =
"""
          
          json_object = json.dumps(jsonout, indent = 4) 

          end = """
var sort_by = function(field, reverse, primer){

   var key = primer ?
       function(x) {return primer(x[field])} :
       function(x) {return x[field]};

   reverse = !reverse ? 1 : -1;

   return function (a, b) {
       return a = key(a), b = key(b), reverse * ((a > b) - (b > a));
     }
}

for(var i = 0; i < data.length; i++) {

    if(data[i].risk=="Information")
    {
        data[i].risk_no=1;
    }

    if(data[i].risk=="Low")
    {
        data[i].risk_no=2;
    }

    if(data[i].risk=="Medium")
    {
        data[i].risk_no=3;
    }

    if(data[i].risk=="High")
    {
        data[i].risk_no=4;
    }





}

data.sort(sort_by('risk_no', true, parseInt));



for(var i = 0; i < data.length; i++) {
$('#findings').append("<tbody><tr><th>File</th><td>"+data[i].file+"</td></tr>");
$('#findings').append("<tr><th>Description</th><td>"+data[i].description+"</td></tr>");
$('#findings').append("<tr><th>Severity</th><td>"+data[i].severity+"</td></tr>");
$('#findings').append("<tr><th>Line</th><td>"+data[i].line+"</td></tr></tbody></table>");
$('#findings').append("<hr>");

}


});//]]>

</script>


</head>

 <div class="container-fluid">




<p style="margin-bottom: 25px;"><img src="https://dl.betterscan.io/wp-content/uploads/2022/05/logo-nobackground-164x32-1.png" style="position:relative; top:-40px;"></p>

<div class="tabbable tabs-left">
    <ul class="nav nav-tabs">
        <li class="active"><a href="#overview" data-toggle="tab">Summary</a></li>
    </ul>
    <div class="tab-content">
        <div class="tab-pane fade in active" id="overview">


<div class="alert alert-info">
    <b>Tags</b>:

        Security Final Report


</div>

<section id="information">
    <div class="box">
        <h4>Report</h4>
        <div class="box-content" style="padding: 0;">
            <table class="table">
                <thead>
                    <tr>
                        <th style="border-top: 0;">Type</th>

                         <td style="border-top: 0;">FILE</td>
                    </tr>
                </thead>
            </table>
        </div>
    </div>


</section>
<hr>

    <section id="file">
    <h4>File Details</h4>
    <div class="box">
        <div class="box-content" style="padding: 0;">
            <table class="table">
                <tbody><tr>
                    <th style="border-top: 0;">File Name</th>
                    <td style="border-top: 0;">report.html</td>
                </tr>
                <tr>
                    <th>File Type</th>
                    <td>data</td>
                </tr>
            </tbody></table>
        </div>
    </div>
</section>



  <div align="center"><h1>Scan Report</h1></div>


<hr>
  <h4>Code</h4>

 <section id="findings1">
    <div class="box">

        <div id="findings" class="box-content" style="padding: 0;">
        </div>
    </div>
</section>

</div>

</body>


</html>


"""
          f = open("report.html", "w")
          f.write(head)
          f.write(json_object)
          f.write(end)
          f.close()

          f = open("report.json", "w")
          f.write(json_object)
          f.close()


          rules = {}
          results = []
          i = 0
          for item in jsonout:

                short_description = item['description']
                full_description = (item['description'])
                message = item['description']
                if not valid:
                  fname = "Please upgrade to PRO"
                else:
                  fname = item['file']
                line = item['line']

                try:
                  severity = item['severity']
                except:
                  severity = "Warning"
                desc_lower = item['description'].lower()
                res = [ele for ele in high if(ele in desc_lower)]
                if bool(res) is True:
                  severity = "High"
                res = [ele for ele in medium if(ele in desc_lower)]
                if bool(res) is True:
                  severity = "Medium"
               
                rules[i] = {
                        "id": str(i),
                        "name": "BetterscanRule",
                        # This appears as the title on the list and individual issue view
                        "shortDescription": {"text": short_description},
                        # This appears as a sub heading on the individual issue view
                        "fullDescription": {"text": full_description},
                        # This appears on the individual issue view in an expandable box
                        "helpUri": "https://betterscan.io",
                        "help": {
                            "markdown": item['description'],
                            # This property is not used if markdown is provided, but is required
                            "text": "",
                            },
                        "defaultConfiguration": {"level": severity},
                        "properties": {"tags": ["security"]},
                        }


                result = {
                        "ruleId": str(i),
                        # This appears in the line by line highlight on the individual issue view
                        "message": {"text": message},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": str(fname)},
                                    "region": {"startLine": int(line)},
                                    }
                                }
                            ],
                        }
                results.append(result)
                i=i+1

          out = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Betterscan", "informationUri": "https://betterscan.io", "semanticVersion": "0.9.9", "rules": list(rules.values())}},
                    "results": results,
                }
            ],
          }

          with open('report.sarif', 'w') as f:
            json.dump(out, f)
         
          print("Check your report in report.html file")

          if not valid:
            print("This scan will have all the features with PRO version :thumbs_up: Limited Lifetime deal with this [link=https://buy.betterscan.io]link[/link] https://buy.betterscan.io")
          else:
            print("Thank you for using the PRO version. :thumbs_up:")
