# -------------------------------------------------------------------------
#
#  Part of the CodeChecker project, under the Apache License v2.0 with
#  LLVM Exceptions. See LICENSE for license information.
#  SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
# -------------------------------------------------------------------------
"""
Contains housekeeping routines that are used to remove expired, obsolete,
or dangling records from the database.
"""
from datetime import datetime, timedelta
from typing import Dict

import sqlalchemy

from codechecker_api.codeCheckerDBAccess_v6.ttypes import Severity

from codechecker_common import util
from codechecker_common.logger import get_logger

from .database import DBSession
from .run_db_model import \
    AnalysisInfo, \
    BugPathEvent, BugReportPoint, \
    Comment, Checker, \
    File, FileContent, \
    Report, ReportAnalysisInfo, RunHistoryAnalysisInfo, RunLock

LOG = get_logger('server')
RUN_LOCK_TIMEOUT_IN_DATABASE = 30 * 60  # 30 minutes.
SQLITE_LIMIT_COMPOUND_SELECT = 500


def remove_expired_data(product):
    """Remove information that has timed out from the database."""
    remove_expired_run_locks(product)


def remove_unused_data(product):
    """Remove dangling data (files, comments, etc.) from the database."""
    remove_unused_files(product)
    remove_unused_comments(product)
    remove_unused_analysis_info(product)


def update_contextual_data(product, context):
    """
    Updates information in the database that comes from potentially changing
    contextual configuration of the server package.
    """
    upgrade_severity_levels(product, context.checker_labels)


def remove_expired_run_locks(product):
    with DBSession(product.session_factory) as session:
        LOG.debug("[%s] Garbage collection of expired run locks started...",
                  product.endpoint)
        try:
            locks_expired_at = datetime.now() - timedelta(
                seconds=RUN_LOCK_TIMEOUT_IN_DATABASE)

            count = session.query(RunLock) \
                .filter(RunLock.locked_at < locks_expired_at) \
                .delete(synchronize_session=False)
            if count:
                LOG.debug("%d expired run locks deleted.", count)

            session.commit()

            LOG.debug("[%s] Garbage collection of expired run locks "
                      "finished.", product.endpoint)
        except (sqlalchemy.exc.OperationalError,
                sqlalchemy.exc.ProgrammingError) as ex:
            LOG.error("[%s] Failed to remove expired run locks: %s",
                      product.endpoint, str(ex))


def remove_unused_files(product):
    # File deletion is a relatively slow operation due to database cascades.
    # Removing files in big chunks prevents reaching a potential database
    # statement timeout. This hard-coded value is a safe choice according to
    # some measurements. Maybe this could be a command-line parameter. But in
    # the long terms we are planning to reduce cascade deletes by redesigning
    # bug_path_events and bug_report_points tables.
    CHUNK_SIZE = 500_000
    with DBSession(product.session_factory) as session:
        LOG.debug("[%s] Garbage collection of dangling files started...",
                  product.endpoint)
        try:
            bpe_files = session.query(BugPathEvent.file_id) \
                .group_by(BugPathEvent.file_id) \
                .subquery()
            brp_files = session.query(BugReportPoint.file_id) \
                .group_by(BugReportPoint.file_id) \
                .subquery()

            files_to_delete = session.query(File.id) \
                .filter(File.id.notin_(bpe_files), File.id.notin_(brp_files))
            files_to_delete = map(lambda x: x[0], files_to_delete)

            total_count = 0
            for chunk in util.chunks(iter(files_to_delete), CHUNK_SIZE):
                q = session.query(File) \
                    .filter(File.id.in_(chunk))
                count = q.delete(synchronize_session=False)
                if count:
                    total_count += count

            if total_count:
                LOG.debug("%d dangling files deleted.", total_count)

            files = session.query(File.content_hash) \
                .group_by(File.content_hash) \
                .subquery()

            session.query(FileContent) \
                .filter(FileContent.content_hash.notin_(files)) \
                .delete(synchronize_session=False)

            session.commit()

            LOG.debug("[%s] Garbage collection of dangling files finished.",
                      product.endpoint)
        except (sqlalchemy.exc.OperationalError,
                sqlalchemy.exc.ProgrammingError) as ex:
            LOG.error("[%s] Failed to remove unused files: %s",
                      product.endpoint, str(ex))


def remove_unused_comments(product):
    with DBSession(product.session_factory) as session:
        LOG.debug("[%s] Garbage collection of dangling comments started...",
                  product.endpoint)
        try:
            report_hashes = session.query(Report.bug_id) \
                .group_by(Report.bug_id) \
                .subquery()

            count = session.query(Comment) \
                .filter(Comment.bug_hash.notin_(report_hashes)) \
                .delete(synchronize_session=False)
            if count:
                LOG.debug("%d dangling comments deleted.", count)

            session.commit()

            LOG.debug("[%s] Garbage collection of dangling comments "
                      "finished.", product.endpoint)
        except (sqlalchemy.exc.OperationalError,
                sqlalchemy.exc.ProgrammingError) as ex:
            LOG.error("[%s] Failed to remove dangling comments: %s",
                      product.endpoint, str(ex))


def remove_unused_analysis_info(product):
    # Analysis info deletion is a relatively slow operation due to database
    # cascades. Removing files in smaller chunks prevents reaching a potential
    # database statement timeout. This hard-coded value is a safe choice
    # according to some measurements.
    CHUNK_SIZE = 500
    with DBSession(product.session_factory) as session:
        LOG.debug("[%s] Garbage collection of dangling analysis info "
                  "started...", product.endpoint)
        try:
            to_delete = session.query(AnalysisInfo.id) \
                .join(
                    RunHistoryAnalysisInfo,
                    RunHistoryAnalysisInfo.c.analysis_info_id ==
                    AnalysisInfo.id,
                    isouter=True) \
                .join(
                    ReportAnalysisInfo,
                    ReportAnalysisInfo.c.analysis_info_id == AnalysisInfo.id,
                    isouter=True) \
                .filter(
                    RunHistoryAnalysisInfo.c.analysis_info_id.is_(None),
                    ReportAnalysisInfo.c.analysis_info_id.is_(None))

            to_delete = map(lambda x: x[0], to_delete)

            total_count = 0
            for chunk in util.chunks(to_delete, CHUNK_SIZE):
                count = session.query(AnalysisInfo) \
                    .filter(AnalysisInfo.id.in_(chunk)) \
                    .delete(synchronize_session=False)
                if count:
                    total_count += count

            if total_count:
                LOG.debug("[%s] %d dangling analysis info deleted.",
                          product.endpoint, total_count)

            session.commit()

            LOG.debug("[%s] Garbage collection of dangling analysis info "
                      "finished.", product.endpoint)
        except (sqlalchemy.exc.OperationalError,
                sqlalchemy.exc.ProgrammingError) as ex:
            LOG.error("[%s] Failed to remove dangling analysis info: %s",
                      product.endpoint, str(ex))


def upgrade_severity_levels(product, checker_labels):
    """
    Updates the potentially changed severities to reflect the data in the
    current label configuration files.
    """
    with DBSession(product.session_factory) as session:
        LOG.debug("[%s] Upgrading severity levels started...",
                  product.endpoint)
        try:
            count = 0
            for analyzer in sorted(checker_labels.get_analyzers()):
                checkers_for_analyzer_in_database = session \
                    .query(Checker.id,
                           Checker.checker_name,
                           Checker.severity) \
                    .filter(Checker.analyzer_name == analyzer) \
                    .all()
                for checker_row in checkers_for_analyzer_in_database:
                    checker: str = checker_row.checker_name
                    old_severity_db: int = checker_row.severity
                    try:
                        old_severity: str = \
                            Severity._VALUES_TO_NAMES[old_severity_db]
                    except KeyError:
                        LOG.error("[%s] Checker '%s/%s' contains invalid "
                                  "severity %d, considering as if "
                                  "'UNSPECIFIED' (0)!",
                                  product.endpoint,
                                  analyzer, checker,
                                  old_severity_db)
                        old_severity_db, old_severity = 0, "UNSPECIFIED"
                    new_severity: str = \
                        checker_labels.severity(checker, analyzer)

                    if old_severity == new_severity:
                        continue

                    if new_severity == "UNSPECIFIED":
                        # No exact match for the checker's name in the
                        # label config for the analyzer. This can mean that
                        # the records are older than a change in the checker
                        # naming scheme (e.g., cppchecker results pre-2021).
                        LOG.warning("[%s] Checker '%s/%s' (database severity: "
                                    "'%s' (%d)) does not have a corresponding "
                                    "entry in the label config file.",
                                    product.endpoint,
                                    analyzer, checker,
                                    old_severity, old_severity_db)

                        new_sev_attempts: Dict[str, str] = {
                            chk_name: severity
                            for chk_name, severity in
                            ((name_attempt,
                              checker_labels.severity(name_attempt, analyzer))
                             for name_attempt in [
                                 "%s.%s" % (analyzer, checker),
                                 "%s-%s" % (analyzer, checker),
                                 "%s/%s" % (analyzer, checker)
                             ])
                            if severity != "UNSPECIFIED"
                        }

                        if len(new_sev_attempts) == 0:
                            LOG.debug("[%s] %s/%s: Keeping the old severity "
                                      "intact...",
                                      product.endpoint, analyzer, checker)
                            continue
                        if len(new_sev_attempts) >= 2 and \
                                len(set(new_sev_attempts.values())) >= 2:
                            LOG.error("[%s] %s/%s: Multiple similar checkers "
                                      "WITH CONFLICTING SEVERITIES were "
                                      "found instead: %s",
                                      product.endpoint,
                                      analyzer, checker,
                                      str(list(new_sev_attempts.items())))
                            LOG.debug("[%s] %s/%s: Keeping the old severity "
                                      "intact...",
                                      product.endpoint, analyzer, checker)
                            continue
                        if len(set(new_sev_attempts.values())) == 1:
                            attempted_name, new_severity = \
                                next(iter(sorted(new_sev_attempts.items())))

                            LOG.info("[%s] %s/%s: Found similar checker "
                                     "'%s/%s' (severity: '%s'), using this "
                                     "for the upgrade.",
                                     product.endpoint,
                                     analyzer, checker,
                                     analyzer, attempted_name,
                                     new_severity)
                            if old_severity == new_severity:
                                continue

                    new_severity_db: int = \
                        Severity._NAMES_TO_VALUES[new_severity]

                    LOG.info("[%s] Upgrading the severity of checker "
                             "'%s/%s' from '%s' (%d) to '%s' (%d).",
                             product.endpoint,
                             analyzer, checker,
                             old_severity, old_severity_db,
                             new_severity, new_severity_db)
                    session.query(Checker) \
                        .filter(Checker.id == checker_row.id) \
                        .update({Checker.severity: new_severity_db})
                    count += 1

                session.flush()

            if count:
                LOG.debug("[%s] %d checker severities upgraded.",
                          product.endpoint, count)

            session.commit()

            LOG.debug("[%s] Upgrading severity levels finished.",
                      product.endpoint)
        except (sqlalchemy.exc.OperationalError,
                sqlalchemy.exc.ProgrammingError) as ex:
            LOG.error("[%s] Failed to upgrade severity levels: %s",
                      product.endpoint, str(ex))
