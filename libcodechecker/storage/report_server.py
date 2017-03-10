# -------------------------------------------------------------------------
#                     The CodeChecker Infrastructure
#   This file is distributed under the University of Illinois Open Source
#   License. See LICENSE.TXT for details.
# -------------------------------------------------------------------------

from __future__ import print_function
from __future__ import unicode_literals

import datetime
import errno
import hashlib
import ntpath
import os
import socket
import sys

import sqlalchemy

from thrift.protocol import TBinaryProtocol
from thrift.server import TServer
from thrift.transport import TSocket
from thrift.transport import TTransport

from DBThriftAPI import CheckerReport
from DBThriftAPI.ttypes import *

from libcodechecker import database_handler
from libcodechecker import decorators
from libcodechecker.logger import LoggerFactory
from libcodechecker.profiler import timeit

from libcodechecker.orm_model import *

LOG = LoggerFactory.get_new_logger('CC SERVER')

if os.environ.get('CODECHECKER_ALCHEMY_LOG') is not None:
    import logging

    logging.basicConfig()
    logging.getLogger('sqlalchemy.engine').setLevel(logging.DEBUG)
    logging.getLogger('sqlalchemy.orm').setLevel(logging.DEBUG)


class CheckerReportHandler(object):
    """
    Class to handle requests from the CodeChecker script to store run
    information to the database.
    """

    @decorators.catch_sqlalchemy
    @timeit
    def store_report_comment(self, report_id, comment, comment_by='CodeChecker'):

        report_comment = ReportComment(report_id, comment, comment_by)
        self.session.add(report_comment)
        self.session.commit()
    

    @decorators.catch_sqlalchemy
    @timeit
    def addCheckerRun(self, command, name, version, start_date):
        """
        Store checker run related data to the database.
        By default updates the results if name already exists.
        Using the force flag removes existing analysis results for a run.
        """

        run = self.session.query(Run).filter(Run.name == name).one_or_none()
        if run:
            # FIXME there is already a run delete and create a new run
            # remove reports which belong only to this run

            run.start(start_date)
            run.set_version(version)

            run_meta = self.session.query(RunMeta).get(run_id)
            run_meta.set_run_cmd(command)

            self.session.add(run)
            self.session.add(run_meta)
            self.session.commit()

            return run.run_id
        else:
            # There is no run create new.
            run = Run(name)
            run.set_version(version)
            run.start(start_date)
            self.session.add(run)
            self.session.commit()

            run_id = run.run_id

            # initialize meta information for the run
            run_meta = RunMeta(run_id)
            run_meta.set_run_cmd(command)
            self.session.add(run_meta)
            self.session.commit()

            return run_id

    @decorators.catch_sqlalchemy
    @timeit
    def finishCheckerRun(self, run_id, finish_date):
        """
        """
        LOG.debug('Finishing run: '+ str(run_id))
        run = self.session.query(Run).get(run_id)

        LOG.debug(run.run_id)
        LOG.debug(run.start_date)
        LOG.debug(run.end_date)
        if not run:
            return False

        run.finish(finish_date)
        self.session.commit()
        return True

    @decorators.catch_sqlalchemy
    @timeit
    def replaceConfigInfo(self, run_id, config_values):
        # FIXME store configuration
        #"""
        #Removes all the previously stored config information and stores the
        #new values.
        #"""
        #count = self.session.query(Config) \
        #    .filter(Config.run_id == run_id) \
        #    .delete()
        #LOG.debug('Config: ' + str(count) + ' removed item.')

        #configs = [Config(
        #    run_id, info.checker_name, info.attribute, info.value) for
        #    info in config_values]
        #self.session.bulk_save_objects(configs)
        #self.session.commit()
        return True

    @decorators.catch_sqlalchemy
    @timeit
    def storeCompilationAction(self,
                               run_id,
                               compilation_cmd_id,
                               compilation_cmd):
        """
        Store the compilation action to a run.
        """
        try:
            cmp_action = self.session.query(CompilationAction).get(compilation_cmd_id)
            if not cmp_action:

                LOG.debug("Storing compilation commmand.")

                comp_action = CompilationAction(compilation_cmd_id,
                                                run_id,
                                                compilation_cmd)
                self.session.add(comp_action)
                self.session.commit()
                return True

            return False

        except Exception as ex:
            LOG.error(ex)
            raise


    @decorators.catch_sqlalchemy
    @timeit
    def storeAnalysisAction(self,
                            run_id,
                            analysis_cmd,
                            analyzer_type,
                            analyzed_source_file,
                            msg):
        """
        Store the analysis actions with some meta information.
        """
        try:

            aaction_hash = hashlib.sha1(analysis_cmd).hexdigest()

            LOG.debug("checking analysis action")
            analysis_action = self.session.query(AnalysisAction).get(aaction_hash)
            LOG.debug("checking analysis action done")
            LOG.debug(analysis_action)
            if not analysis_action:
                LOG.debug("storing analysis action")
                analysis_action = AnalysisAction(aaction_hash,
                                                 analyzer_type,
                                                 run_id)
                self.session.add(analysis_action)

                aaction_meta = AnalysisActionMeta(aaction_hash,
                                                  analysis_cmd)
                aaction_meta.set_msg(msg)
                self.session.add(aaction_meta)

            return aaction_hash

        except Exception as ex:
            LOG.error(ex)
            raise

        finally:
            self.session.commit()


    @decorators.catch_sqlalchemy
    @timeit
    def needFileContent(self, source_content_hash):
        """
        Check if file content is needed based on the content hash.
        """
        try:
            f = self.session.query(File).get(source_content_hash)
            if f:
                return False
            return True
        except Exception as ex:
            raise shared.ttypes.RequestFailed(
                shared.ttypes.ErrorCode.GENERAL,
                str(ex))


    @decorators.catch_sqlalchemy
    @timeit
    def addTagToIssue(self, tag_name, report_id):
        # TODO move out to shared module

        tag = self.session.query(Tag) \
                .filter(Tag.name == tag_name).one_or_none()

        if not tag or tag.kind != 'issue':
            # tag not found or tries to apply the wrong kind of tag
            LOG.debug('Failed to apply tag: ' +
                      tag.name + " to issue: " + report_id)
            return False

        r2tag = ReportToTag(report_id, tag.id)
        self.session.add(r2tag)
        self.session.commit()

        comment = "Applying tag: "+str(tag.name)
        self.store_report_comment(report_id, comment)

        return True


    @decorators.catch_sqlalchemy
    @timeit
    def addFileContent(self, file_content_hash, filepath, content):
        """
        Store file and file meta information
        """
        new_file = File(file_content_hash, filepath)
        self.session.add(new_file)
        file_meta = FileMeta(file_content_hash, content)
        self.session.add(file_meta)
        self.session.commit()
        return True


    def storeDiagSections(self, report_id, diag_sections):

        LOG.debug("Storing diagnostic data")
        try:
            for ds in diag_sections:
                dsc = DiagSection(ds.file_id,
                                  report_id,
                                  ds.startLine,
                                  ds.endLine,
                                  ds.startCol,
                                  ds.endCol,
                                  ds.msg,
                                  ds.kind,
                                  ds.path_position)
                self.session.add(dsc)

            self.session.commit()
            LOG.debug("Storing diagnostic sections done")


        except Exception as ex:
            LOG.debug(ex)


    @decorators.catch_sqlalchemy
    @timeit
    def addReport(self, report):
        """
        """
        try:

            rep = self.session.query(Report).get(report.report_id)
            if rep:
                LOG.debug("Report already found")
                return rep.report_id


            report_to_store = Report(report.report_id,
                                     report.report_hash,
                                     report.phash,
                                     report.checker_name,
                                     report.checker_cat,
                                     report.report_type,
                                     report.main_diag_section.msg)

            self.session.add(report_to_store)
            self.session.commit()


            d_sections = report.diagnostic
            d_sections.append(report.main_diag_section)

            self.storeDiagSections(report.report_id, d_sections)
            self.session.commit()

            return report.report_id


        except Exception as ex:
            raise shared.ttypes.RequestFailed(
                shared.ttypes.ErrorCode.GENERAL,
                str(ex))


    @decorators.catch_sqlalchemy
    @timeit
    def storeReportComment(self, report_id, comment, comment_by):
        """
        """
        try:

            LOG.debug("Adding report comment entry.")
            self.store_report_comment(report_id, comment, comment_by)
            return True

        except Exception as ex:
            raise shared.ttypes.RequestFailed(
                shared.ttypes.ErrorCode.GENERAL,
                str(ex))


    @decorators.catch_sqlalchemy
    @timeit
    def addToRun(self, run_id, report_id):
        try:
            added_to_run = self.session.query(RunToReport) \
                    .filter(RunToReport.run_id == run_id,
                            RunToReport.report_id == report_id).one_or_none()

            if not added_to_run:
                LOG.debug("adding new issue to the run")
                LOG.debug(run_id)

                add_to_run = RunToReport(run_id, report_id)
                self.session.add(add_to_run)
                self.session.commit()
            return True

        except Exception as ex:
            raise shared.ttypes.RequestFailed(
                shared.ttypes.ErrorCode.GENERAL,
                str(ex))


    @decorators.catch_sqlalchemy
    @timeit
    def storeTag(self, tag_name, kind):

        try:
            tag = self.session.query(Tag) \
                    .filter(Tag.name == tag_name).one_or_none()
            if not tag:
                LOG.debug("Adding new tag " + tag_name + " " + kind)
                new_tag = Tag(tag_name, kind)
                self.session.add(new_tag)
                self.session.commit()
            else:
                LOG.debug("Tag: "+ tag_name + " already stored.")

            return True

        except Exception as ex:
            raise shared.ttypes.RequestFailed(
                shared.ttypes.ErrorCode.GENERAL,
                str(ex))


    @decorators.catch_sqlalchemy
    @timeit
    def deleteTag(self, tag_name):

        try:
            tag = self.session.query(Tag) \
                    .filter(Tag.name == tag_name).one_or_none()
            if tag:
                self.session.delete(tag)
                self.session.commit()

            return True

        except Exception as ex:
            raise shared.ttypes.RequestFailed(
                shared.ttypes.ErrorCode.GENERAL,
                str(ex))

    @decorators.catch_sqlalchemy
    @timeit
    def suppressReport(self, suppress_report_data):
        """
        Supppress multiple bugs for a run. This can be used before storing
        the suppress file content.

        """

        try:
            # FIXME common method to get suppress tag id
            suppress_tag = self.session.query(Tag) \
                    .filter(Tag.name == "suppress").one_or_none()

            for srd in suppress_report_data:
                report_id = srd.report_id
                sup_report = self.session.query(Suppress).get(srd.report_id)
                LOG.debug(sup_report)

                if sup_report and srd.force_update:
                    LOG.debug('Suppressed report found updating')
                    sup_report.set_comment(srd.comment)
                    self.session.add(sup_report)
                    self.session.commit()
                    self.store_report_comment(srd.report_id, 'Suppress updated')
                else:
                    LOG.debug('Suppressed report not found')
                    srp = Suppress(srd.report_id, srd.file_name, srd.comment)
                    self.session.add(srp)
                    self.session.commit()

                    srp_tag = self.session.query(ReportToTag) \
                            .filter(ReportToTag.report_id == srd.report_id,
                                    ReportToTag.tagid == suppress_tag.id) \
                                    .one_or_none()
                    if not srp_tag:
                        LOG.debug('adding suppress tag')
                        new_tag = ReportToTag(srd.report_id,
                                                   suppress_tag.id)
                        self.session.add(new_tag)
                        self.session.commit()

                    LOG.debug('adding comment')
                    self.store_report_comment(srd.report_id, 'Report suppressed')

            return True

        except Exception as ex:
            LOG.error(str(ex))
            return False


    @decorators.catch_sqlalchemy
    @timeit
    def unsuppressReport(self, report_id):
        """
        Only the database is modified.
        """
        try:

            suppress_tag = self.session.query(Tag) \
                    .filter(Tag.name == "suppress").one_or_none()

            suppressed = self.session.query(Suppress) \
                    .filter(Suppress.report_id == report_id).delete()

            self.session.commit()

            self.store_report_comment(srd.report_id, 'Report unsuppressed.')

        except Exception as ex:
            LOG.error(str(ex))
            return False

        return True

    @decorators.catch_sqlalchemy
    @timeit
    def addSkipPath(self, run_id, paths):
        # FIXME store skip information
        """
        """
        #count = self.session.query(SkipPath) \
        #    .filter(SkipPath.run_id == run_id) \
        #    .delete()
        #LOG.debug('SkipPath: ' + str(count) + ' removed item.')

        #skipPathList = []
        #for path, comment in paths.items():
        #    skipPath = SkipPath(run_id, path, comment)
        #    skipPathList.append(skipPath)
        #self.session.bulk_save_objects(skipPathList)
        #self.session.commit()
        return True

    @decorators.catch_sqlalchemy
    @timeit
    def stopServer(self):
        """
        """
        self.session.commit()
        sys.exit(0)

    def __init__(self, session):
        self.session = session


def run_server(port, db_uri, callback_event=None):
    LOG.debug('Starting CodeChecker server ...')

    try:
        engine = database_handler.SQLServer.create_engine(db_uri)

        LOG.debug('Creating new database session.')
        session = CreateSession(engine)

    except sqlalchemy.exc.SQLAlchemyError as alch_err:
        LOG.error(str(alch_err))
        sys.exit(1)

    session.autoflush = False  # Autoflush is enabled by default.

    LOG.debug('Starting thrift server.')
    try:
        # Start thrift server.
        handler = CheckerReportHandler(session)

        processor = CheckerReport.Processor(handler)
        transport = TSocket.TServerSocket(port=port)
        tfactory = TTransport.TBufferedTransportFactory()
        pfactory = TBinaryProtocol.TBinaryProtocolFactory()

        server = TServer.TThreadPoolServer(processor,
                                           transport,
                                           tfactory,
                                           pfactory,
                                           daemon=True)

        LOG.info('Waiting for check results on [' + str(port) + ']')
        if callback_event:
            callback_event.set()
        LOG.debug('Starting to serve.')
        server.serve()
        session.commit()
    except socket.error as sockerr:
        LOG.error(str(sockerr))
        if sockerr.errno == errno.EADDRINUSE:
            LOG.error('Checker port ' + str(port) + ' is already used!')
        sys.exit(1)
    except Exception as err:
        LOG.error(str(err))
        session.commit()
        sys.exit(1)
