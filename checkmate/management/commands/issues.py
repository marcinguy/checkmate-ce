# -*- coding: utf-8 -*-
import pprint

from checkmate.lib.models import Issue
from checkmate.contrib.plugins.git.models import GitSnapshot
from checkmate.management.commands.base import BaseCommand
import logging
import json

logger = logging.getLogger(__name__)


class Command(BaseCommand):

    """
    Returns a list of issues for the current snapshot or file revision.
    """

    def run(self):
        snapshot_pk = None
        filenames = None
        ashtml = 0
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

        if ashtml == 0:
          for issue in issues:
              print(("%(analyzer)s\t%(code)s\t" % {'analyzer': issue['analyzer'],
                                                 'code': issue['code']}))
        else:
          jsonout = []
          out = {}
          for issue in issues:
              out['alert'] =  issue['code']
              out['description'] = issue['data']
              jsonout.append(out)
       

          head = """
<!DOCTYPE html>
<html>
<head>
  <meta http-equiv="content-type" content="text/html; charset=UTF-8">
  <title>Report</title>
  <script type='text/javascript' src='https://code.jquery.com/jquery-2.1.0.js'></script>

  <script type='text/javascript' src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.1/js/bootstrap.min.js"></script>

  <link href="https://www.scanmycode.io/assets/css/reportstyle.css" rel="stylesheet">





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
$('#findings').append("<tbody><tr><th>Finding</th><td>"+data[i].alert+"</td></tr>");
$('#findings').append("<tr><th>Description</th><td>"+data[i].description+"</td></tr></tbody></table>");
$('#hr').append("<hr>");

}


});//]]>

</script>


</head>

 <div class="container-fluid">




<p style="margin-bottom: 25px;"><img src="https://www.scanmycode.io/wp-content/uploads/2022/05/logo-nobackground-164x32-1.png" style="position:relative; top:-40px;"></p>

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
                    <td style="border-top: 0;">index.html</td>
                </tr>
                <tr>
                    <th>File Size</th>
                    <td>5136</td>
                </tr>
                <tr>
                    <th>File Type</th>
                    <td>data</td>
                </tr>
                <tr>
                    <th>MD5</th>
                    <td>eacf331f0ffc35d4b482f1d15a887d3b</td>
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
          f = open("report.html", "a")
          f.write(head)
          f.write(json_object)
          f.write(end)
          f.close()
