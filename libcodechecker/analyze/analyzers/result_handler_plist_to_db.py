# -------------------------------------------------------------------------
#                     The CodeChecker Infrastructure
#   This file is distributed under the University of Illinois Open Source
#   License. See LICENSE.TXT for details.
# -------------------------------------------------------------------------

from abc import ABCMeta
import codecs
import hashlib
import ntpath
import os
import zlib

import shared

from libcodechecker import client
from libcodechecker import logger
from libcodechecker import suppress_handler
from libcodechecker.analyze import plist_parser
from libcodechecker.analyze.analyzers.result_handler_base import ResultHandler
from libcodechecker.logger import LoggerFactory

LOG = LoggerFactory.get_new_logger('PLIST TO DB')


def convert_section_kind(name):
    return shared.ttypes.DiagSectionKind._NAMES_TO_VALUES[name.upper()]

class PlistToDB(ResultHandler):
    """
    Result handler for processing a plist file with the
    analysis results and stores them to the database.
    """

    __metaclass__ = ABCMeta

    def __init__(self, buildaction, workspace, run_id):
        super(PlistToDB, self).__init__(buildaction, workspace)
        self.__run_id = run_id

    def __store_file(self, connection, file_name):
        """
        Send content of file to the server if needed.
        """
        content_hash = hashlib.sha1(open(file_name, 'rb').read()).hexdigest()

        if connection.need_file_content(content_hash):

            # Sometimes the file doesn't exist, e.g. when the input of the
            # analysis is pure plist files.
            if not os.path.isfile(file_name):
                LOG.debug(file_name + ' not found, and will not be stored.')
                return None

            # changed here all is read up as utf-8
            with codecs.open(file_name, encoding='utf-8') as source_file:
                compressed_file = zlib.compress(source_file.read(),
                                                zlib.Z_BEST_COMPRESSION)
                LOG.debug('storing file content to the database')
                connection.add_file_content(content_hash, file_name,
                                            compressed_file)
        return content_hash

    def __convertToDiagnosticSection(self, diag_section, file_ids):
        """
        Convert DiagSection to the thrift DiagnosticSection type.
        """
        return shared.ttypes.DiagnosticSection(
            diag_section.start_pos.line,
            diag_section.start_pos.col,
            diag_section.end_pos.line,
            diag_section.end_pos.col,
            convert_section_kind(diag_section.kind),
            diag_section.msg,
            diag_section.path_position,
            file_ids[diag_section.start_pos.file_path])


    def __store_reports(self, run_id, files, reports, connection, analisys_id):
        """
        Store the reports to the database.
        """

        LOG.debug("Storing reports.")
        try:
            file_ids = {}

            # Skipping bugs in header files handled here.
            for report in reports:

                diag_section = report.main_section

                # Skip list handler can be None if no config file is set.
                if self.skiplist_handler:
                    if diag_section and self.skiplist_handler.should_skip(
                            diag_section.start_pos.file_path):
                        # Issue #20: this report is in a file which should be skipped
                        LOG.debug(report.hash_value + ' is skipped (in ' +
                                  diag_section.start_pos.file_path + ")")
                        continue

                # collect all the source files which should be stored
                files_in_path = set()

                for p in report.get_path().get_diag_sections():
                    files_in_path.add(p.start_pos.file_path)
                    files_in_path.add(p.end_pos.file_path)

                files_in_path.add(report.main_section.start_pos.file_path)
                files_in_path.add(report.main_section.end_pos.file_path)

                for source_file in files_in_path:
                    content_hash = self.__store_file(connection, source_file)
                    file_ids[source_file] = content_hash
                    LOG.debug("Storing source file " +
                              source_file + " " + content_hash + " is done.")

                main_diag_section = self.__convertToDiagnosticSection(
                        report.main_section, file_ids)

                diag_sections = []
                # path independent diagnostic sections
                for ds in report.diag_sections():
                    diag_sections.append(
                            self.__convertToDiagnosticSection(ds, file_ids))

                # diagnostic sections which belong to a path
                for ds in report.get_path().get_diag_sections():
                    diag_sections.append(
                            self.__convertToDiagnosticSection(ds, file_ids))

                severity_name = self.severity_map.get(report.checker_name,
                                                      'UNSPECIFIED')
                severity = severity_name

                report_to_store = shared.ttypes.Report(
                    file_ids[report.main_section.start_pos.file_path],
                    report.report_id,
                    report.get_path().path_hash,
                    report.report_hash,
                    main_diag_section,
                    diag_sections,
                    report.checker_name,
                    report.category,
                    report.type)

                LOG.debug(report_to_store)

                connection.add_report(report_to_store)

                comment = "Detected in run #" + str(run_id)
                connection.add_report_comment(report.report_id,
                        comment, 'CodeChecker')

                connection.add_to_run(run_id, report.report_id)

                # store severity level
                connection.add_tag_to_issue(severity.lower(),
                                            report.report_id)

                # Check for suppress comment.
                # FIXME store suppress information

                sp_handler = suppress_handler.SourceSuppressHandler(report)
                supp = sp_handler.get_suppressed()
                if supp:
                    bug_hash, sp_file_name, sp_comment = supp

                    sp = (report.report_id, sp_file_name, sp_comment)

                    if bug_hash:
                        connection.suppress_reports([sp])
            return 0

        except Exception as ex:
            LOG.debug(ex)
            return 1

    def handle_results(self):
        """
        Send the plist content to the database.
        Server API calls should be used in one connection.
        """

        with client.get_connection() as connection:

            LOG.debug('Storing original build and analyzer command '
                      'to the database.')

            _, source_file_name = ntpath.split(self.analyzed_source_file)


            build_cmd_hash = self.buildaction.original_command_hash

            # FIXME changed here compilatioj action is stored only in debug mode
            if connection.store_compilation_action(self.__run_id,
                    build_cmd_hash, self.buildaction.original_command):
                LOG.error("Failed to store compilation command")

            # FIXME changed here analysis action is stored only in debug mode
            analyzer_cmd = ' '.join(self.analyzer_cmd)
            analysis_action_id = connection.store_analysis_action(
                                           self.__run_id,
                                           analyzer_cmd,
                                           self.buildaction.analyzer_type,
                                           source_file_name,
                                           self.analyzer_stderr)

            LOG.debug(analysis_action_id)
            assert self.analyzer_returncode == 0

            plist_file = self.analyzer_result_file

            try:
                files, bugs = plist_parser.parse_plist(plist_file)
            except Exception as ex:
                LOG.debug(str(ex))
                msg = 'Parsing the generated result file failed.'
                LOG.error(msg + ' ' + plist_file)
                return 1

            if self.__store_reports(self.__run_id,
                                    files,
                                    bugs,
                                    connection,
                                    analysis_action_id):

                LOG.error("Failed to store reports from result file: " +
                          plist_file)



    def postprocess_result(self):
        """
        No postprocessing required for plists.
        """
        pass
