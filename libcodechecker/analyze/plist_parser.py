# -------------------------------------------------------------------------
#                     The CodeChecker Infrastructure
#   This file is distributed under the University of Illinois Open Source
#   License. See LICENSE.TXT for details.
# -------------------------------------------------------------------------
"""
Parse the plist output of an analyzer and convert it to a report for
further processing.
"""

import plistlib
import traceback
from xml.parsers.expat import ExpatError

from libcodechecker.analyze import plist_helper
from libcodechecker.logger import LoggerFactory

from libcodechecker.report import Report
from libcodechecker.report import DiagSection
from libcodechecker.report import BugPath
from libcodechecker.report import Position

LOG = LoggerFactory.get_new_logger('PLIST_PARSER')


def make_position(pos_map, files):
    return Position(pos_map.line, pos_map.col, files[pos_map.file])


def make_range(array, files, kind):
    if len(array) == 2:
        start = make_position(array[0], files)
        end = make_position(array[1], files)
        return DiagSection(start, end, kind)


def parse_plist(path):
    """
    Parse the reports from a plist file.
    One plist file can contain multiple reports.
    """
    LOG.debug(path)

    reports = []
    files = []
    try:
        plist = plistlib.readPlist(path)

        files = plist['files']

        for diag in plist['diagnostics']:

            message = diag['description']
            checker_name = diag.get('check_name')
            if not checker_name:
                LOG.debug("Check name wasn't found in the plist file. "
                          "Read the user guide!")
                checker_name = plist_helper.get_check_name(message)
                LOG.debug('Guessed check name: ' + checker_name)

            new_report = Report(checker_name,
                             diag['category'],
                             diag['type'])

            # set the main diagnostic section used
            # at high level listing of reports 
            start_pos = Position(line=diag['location']['line'],
                                 col=diag['location']['col'],
                                 filepath=files[diag['location']['file']])

            main_section = DiagSection(start_pos,
                                       end_pos=None,
                                       kind="main",
                                       msg=message)

            new_report.main_section = main_section

            # collect additional diagnostic sections which belong to a path
            for item in diag['path']:
                # add only event and control items to a bug path
                bug_path = BugPath()

                if item['kind'] == 'event':
                    message = item['message']
                    if 'ranges' in item:
                        for arr in item['ranges']:
                            source_range = make_range(arr,
                                                      files,
                                                      'event')
                            source_range.msg = message
                            bug_path.add_diag(source_range)
                    else:
                        location = make_position(item['location'], files)
                        source_range = DiagSection(location,
                                                   location,
                                                   message)
                        source_range.msg = message
                        bug_path.add_diag(source_range)


                elif item['kind'] == 'control':
                    for edge in item['edges']:
                        start = make_range(edge.start,
                                           files,
                                           'control')
                        end = make_range(edge.end,
                                         files,
                                         'control')

                        # FIXME previous edge end can be the same and
                        # this start control node possible duplication
                        bug_path.add_diag(start)
                        bug_path.add_diag(end)

                new_report.set_path(bug_path)

            hash_value = diag.get('issue_hash_content_of_line_in_context')
            if not hash_value:
                # Generate some hash for older clang versions.
                LOG.debug("Hash value wasn't found in the plist file. "
                          "Read the user guide!")
                hash_value = plist_helper.gen_bug_hash(new_report)

            new_report.hash_value = hash_value

            reports.append(new_report)

    except ExpatError as err:
        LOG.debug('Failed to process plist file: ' + path)
        LOG.debug(err)
    except AttributeError as ex:
        LOG.debug(ex)
    except Exception as ex:
        LOG.debug(ex)
    finally:
        return files, reports
